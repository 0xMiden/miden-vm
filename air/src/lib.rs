#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::borrow::Borrow;

use alloc::vec::Vec;

use miden_core::{
    ProgramInfo, StackInputs, StackOutputs, field::ExtensionField,
    precompile::PrecompileTranscriptState,
};

pub mod config;
mod constraints;

pub mod unedited_constraints;
pub use unedited_constraints::*;
use p3_miden_air::BusType;

pub mod trace;
use trace::{AuxTraceBuilder, MainTraceRow, TRACE_WIDTH};

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        utils::{
            ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, ToElements,
        },
    };
    pub use miden_crypto::stark::air::{Air, AirBuilder, BaseAir, MidenAir, MidenAirBuilder};
}

pub use export::*;

pub const NUM_PERIODIC_VALUES: usize = 29;
pub const PERIOD: usize = 8;

// PUBLIC INPUTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct PublicInputs {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    pc_transcript_state: PrecompileTranscriptState,
}

impl PublicInputs {
    /// Creates a new instance of `PublicInputs` from program information, stack inputs and outputs,
    /// and the precompile transcript state (capacity of an internal sponge).
    pub fn new(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        pc_transcript_state: PrecompileTranscriptState,
    ) -> Self {
        Self {
            program_info,
            stack_inputs,
            stack_outputs,
            pc_transcript_state,
        }
    }

    pub fn stack_inputs(&self) -> StackInputs {
        self.stack_inputs
    }

    pub fn stack_outputs(&self) -> StackOutputs {
        self.stack_outputs
    }

    pub fn program_info(&self) -> ProgramInfo {
        self.program_info.clone()
    }

    /// Returns the precompile transcript state.
    pub fn pc_transcript_state(&self) -> PrecompileTranscriptState {
        self.pc_transcript_state
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements
    /// - stack inputs
    /// - stack outputs
    /// - precompile transcript state
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut result = self.program_info.to_elements();
        result.extend_from_slice(self.stack_inputs.as_ref());
        result.extend_from_slice(self.stack_outputs.as_ref());
        result.extend_from_slice(self.pc_transcript_state.as_ref());
        result
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.program_info.write_into(target);
        self.stack_inputs.write_into(target);
        self.stack_outputs.write_into(target);
        self.pc_transcript_state.write_into(target);
    }
}

impl Deserializable for PublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let program_info = ProgramInfo::read_from(source)?;
        let stack_inputs = StackInputs::read_from(source)?;
        let stack_outputs = StackOutputs::read_from(source)?;
        let pc_transcript_state = PrecompileTranscriptState::read_from(source)?;

        Ok(PublicInputs {
            program_info,
            stack_inputs,
            stack_outputs,
            pc_transcript_state,
        })
    }
}

// PROCESSOR AIR
// ================================================================================================

/// Miden VM Processor AIR implementation.
///
/// This struct defines the constraints for the Miden VM processor.
/// Generic over aux trace builder to support different extension fields.
pub struct ProcessorAir<A, EF, B = ()>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>
{
    inner: Option<A>,
    /// Auxiliary trace builder for generating auxiliary columns.
    aux_builder: Option<B>,
    phantom: core::marker::PhantomData<EF>,
}

impl<A, EF> ProcessorAir<A, EF, ()>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>
{
    /// Creates a new ProcessorAir without auxiliary trace support.
    pub fn new(a: Option<A>) -> Self {
        Self { 
            inner: a,
            aux_builder: None,
            phantom: core::marker::PhantomData
        }
    }
}

impl<A, EF, B> ProcessorAir<A, EF, B>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    /// Creates a new ProcessorAir with auxiliary trace support.
    pub fn with_aux_builder(a: Option<A>, builder: B) -> Self {
        Self { 
            inner: a,
            aux_builder: Some(builder),
            phantom: core::marker::PhantomData
        }
    }
}

use p3_matrix::dense::RowMajorMatrix;

use crate::trace::AUX_TRACE_WIDTH;

impl<A, EF, B> MidenAir<Felt, EF> for ProcessorAir<A, EF, B>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn width(&self) -> usize {
        self.inner.as_ref().map(|inner| inner.width()).unwrap_or(TRACE_WIDTH)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.inner.as_ref().map(|inner| inner.preprocessed_trace()).unwrap_or(None)
    }

    fn num_public_values(&self) -> usize {
        self.inner.as_ref().map(|inner| inner.num_public_values()).unwrap_or(0) // todo
    }

    fn periodic_table(&self) -> Vec<Vec<Felt>> {
        self.inner.as_ref().map(|inner| inner.periodic_table()).unwrap_or(
            vec![
                vec![Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)],
                vec![Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(0)],
                vec![Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)],
                vec![Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1), Felt::new(0)],
                vec![Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1)],
                vec![Felt::new(5789762306288267264), Felt::new(12987190162843097088), Felt::new(18072785500942327808), Felt::new(5674685213610122240), Felt::new(4887609836208846848), Felt::new(16308865189192448000), Felt::new(7123075680859040768), Felt::new(0)],
                vec![Felt::new(6522564764413702144), Felt::new(653957632802705280), Felt::new(6200974112677013504), Felt::new(5759084860419474432), Felt::new(3027115137917284352), Felt::new(11977192855656443904), Felt::new(1034205548717903104), Felt::new(0)],
                vec![Felt::new(9602914297752487936), Felt::new(8110510111539675136), Felt::new(8884468225181997056), Felt::new(17021852944633065472), Felt::new(2955076958026921984), Felt::new(13277683694236792832), Felt::new(14345062289456084992), Felt::new(0)],
                vec![Felt::new(16657542370200465408), Felt::new(2872078294163232256), Felt::new(13066900325715521536), Felt::new(6252096473787587584), Felt::new(7433723648458773504), Felt::new(2600778905124452864), Felt::new(17036731477169661952), Felt::new(0)],
                vec![Felt::new(17809893479458207744), Felt::new(4441654670647621120), Felt::new(17682092219085883392), Felt::new(13943282657648898048), Felt::new(9595098600469471232), Felt::new(12532242556065779712), Felt::new(7717824418247931904), Felt::new(0)],
                vec![Felt::new(107145243989736512), Felt::new(4038207883745915904), Felt::new(10599526828986757120), Felt::new(1352748651966375424), Felt::new(10528569829048483840), Felt::new(14594890931430969344), Felt::new(3019070937878604288), Felt::new(0)],
                vec![Felt::new(6388978042437517312), Felt::new(5613464648874829824), Felt::new(975003873302957312), Felt::new(17110913224029904896), Felt::new(7864689113198940160), Felt::new(7291784239689209856), Felt::new(11403792746066868224), Felt::new(0)],
                vec![Felt::new(15844067734406017024), Felt::new(13222989726778339328), Felt::new(8264241093196931072), Felt::new(1003883795902368384), Felt::new(17533723827845969920), Felt::new(5514718540551361536), Felt::new(10280580802233112576), Felt::new(0)],
                vec![Felt::new(9975000513555218432), Felt::new(3037761201230264320), Felt::new(10065763900435474432), Felt::new(4141870621881018368), Felt::new(5781638039037711360), Felt::new(10025733853830934528), Felt::new(337153209462421248), Felt::new(0)],
                vec![Felt::new(3344984123768313344), Felt::new(16683759727265179648), Felt::new(2181131744534710272), Felt::new(8121410972417424384), Felt::new(17024078752430718976), Felt::new(7293794580341021696), Felt::new(13333398568519923712), Felt::new(0)],
                vec![Felt::new(9959189626657347584), Felt::new(8337364536491240448), Felt::new(6317303992309419008), Felt::new(14300518605864919040), Felt::new(109659393484013504), Felt::new(6728552937464861696), Felt::new(3596153696935337472), Felt::new(0)],
                vec![Felt::new(12960773468763564032), Felt::new(3227397518293416448), Felt::new(1401440938888741632), Felt::new(13712227150607669248), Felt::new(7158933660534805504), Felt::new(6332385040983343104), Felt::new(8104208463525993472), Felt::new(0)],
                vec![Felt::new(6077062762357203968), Felt::new(6202948458916100096), Felt::new(8023374565629191168), Felt::new(18389244934624493568), Felt::new(6982293561042363392), Felt::new(3736792340494631424), Felt::new(17130398059294019584), Felt::new(0)],
                vec![Felt::new(15277620170502010880), Felt::new(17690140365333231616), Felt::new(15013690343205953536), Felt::new(16731736864863924224), Felt::new(14065426295947720704), Felt::new(577852220195055360), Felt::new(519782857322262016), Felt::new(0)],
                vec![Felt::new(10063319113072093184), Felt::new(17731621626449383424), Felt::new(9045979173463557120), Felt::new(14512769585918244864), Felt::new(6844229992533661696), Felt::new(4571485474751953408), Felt::new(3611348709641382912), Felt::new(0)],
                vec![Felt::new(14200078843431360512), Felt::new(2897136237748376064), Felt::new(12934431667190679552), Felt::new(10973956031244050432), Felt::new(7446486531695178752), Felt::new(17200392109565784064), Felt::new(18256379591337758720), Felt::new(0)],
                vec![Felt::new(5358738125714196480), Felt::new(3595001575307484672), Felt::new(4485500052507913216), Felt::new(4440209734760478208), Felt::new(16451845770444974080), Felt::new(6689998335515780096), Felt::new(9625384390925084672), Felt::new(0)],
                vec![Felt::new(14233283787297595392), Felt::new(373995945117666496), Felt::new(12489737547229155328), Felt::new(17208448209698889728), Felt::new(7139138592091307008), Felt::new(13886063479078012928), Felt::new(1664893052631119104), Felt::new(0)],
                vec![Felt::new(13792579614346651648), Felt::new(1235734395091296000), Felt::new(9500452585969031168), Felt::new(8739495587021565952), Felt::new(9012006439959783424), Felt::new(14358505101923203072), Felt::new(7629576092524553216), Felt::new(0)],
                vec![Felt::new(11614812331536766976), Felt::new(14172757457833930752), Felt::new(2054001340201038848), Felt::new(17000774922218162176), Felt::new(14619614108529063936), Felt::new(7744142531772273664), Felt::new(3485239601103661568), Felt::new(0)],
                vec![Felt::new(14871063686742261760), Felt::new(707573103686350208), Felt::new(12420704059284934656), Felt::new(13533282547195531264), Felt::new(1394813199588124416), Felt::new(16135070735728404480), Felt::new(9755891797164034048), Felt::new(0)],
                vec![Felt::new(10148237148793042944), Felt::new(15453217512188186624), Felt::new(355990932618543744), Felt::new(525402848358706240), Felt::new(4635111139507788800), Felt::new(12290902521256030208), Felt::new(15218148195153268736), Felt::new(0)],
                vec![Felt::new(4457428952329675776), Felt::new(219777875004506016), Felt::new(9071225051243524096), Felt::new(16987541523062161408), Felt::new(16217473952264204288), Felt::new(12059913662657710080), Felt::new(16460604813734957056), Felt::new(0)],
                vec![Felt::new(15590786458219171840), Felt::new(17876696346199468032), Felt::new(12766199826003447808), Felt::new(5466806524462796800), Felt::new(10782018226466330624), Felt::new(16456018495793752064), Felt::new(9643968136937730048), Felt::new(0)],
            ]
        )
    }

    fn num_randomness(&self) -> usize {
        self.inner.as_ref().map(|inner| inner.num_randomness()).unwrap_or(trace::AUX_TRACE_RAND_ELEMENTS)
    }

    fn aux_width(&self) -> usize {
        self.inner.as_ref().map(|inner| inner.aux_width()).unwrap_or(AUX_TRACE_WIDTH)
    }

    fn bus_types(&self) -> &[BusType] {
        self.inner.as_ref().map(|inner| inner.bus_types()).unwrap_or(&[]) // todo
    }

    fn build_aux_trace(
        &self,
        main: &p3_matrix::dense::RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> Option<p3_matrix::dense::RowMajorMatrix<Felt>> {
        let _span = tracing::info_span!("build_aux_trace").entered();

        let builders = self.aux_builder.as_ref()?;

        Some(builders.build_aux_columns(main, challenges))
    }
    
    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        if let Some(inner) = &self.inner {
            inner.eval(builder);
        } else {
            use p3_matrix::Matrix;

            use crate::constraints;

            let main = builder.main();

            // Access the two rows: current (local) and next
            let local = main.row_slice(0).expect("Matrix should have at least 1 row");
            let next = main.row_slice(1).expect("Matrix should have at least 2 rows");

            // Use structured column access via MainTraceCols
            let local: &MainTraceRow<AB::Var> = (*local).borrow();
            let next: &MainTraceRow<AB::Var> = (*next).borrow();

            let periodic_values: [_; NUM_PERIODIC_VALUES] =
                builder.periodic_evals().try_into().expect("Wrong number of periodic values");

            // SYSTEM CONSTRAINTS
            constraints::enforce_clock_constraint(builder, local, next);

            // STACK CONSTRAINTS
            //constraints::stack::enforce_stack_boundary_constraints(builder, local);
            //constraints::stack::enforce_stack_transition_constraint(builder, local, next);
            //constraints::stack::enforce_stack_bus_constraint(builder, local);

            // RANGE CHECKER CONSTRAINTS
            constraints::range::enforce_range_boundary_constraints(builder, local);
            constraints::range::enforce_range_transition_constraint(builder, local, next);
            constraints::range::enforce_range_bus_constraint(builder, local);

            // CHIPLETS CONSTRAINTS
            constraints::chiplets::enforce_chiplets_transition_constraint(
                builder,
                local,
                next,
                &periodic_values,
            );
            constraints::chiplets::enforce_chiplets_bus_constraint(builder, local);
        }
    }
}
