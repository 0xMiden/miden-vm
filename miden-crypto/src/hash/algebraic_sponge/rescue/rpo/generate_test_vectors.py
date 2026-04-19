#!/usr/bin/env python3
"""
RPO (Rescue Prime Optimized) test vector generator.

This script generates test vectors for the RPO hash function using the state layout
where rate elements are at positions 0..7 and capacity elements are at positions 8..11.
This corresponds to the layout used in the Rust implementation after the state remapping
in PR #755 (issue #673).

The reference implementation at https://github.com/ASDiscreteMathematics/rpo uses the
original layout where capacity is at positions 0..3 and rate is at positions 4..11.
This script adapts that reference to verify consistency with the new layout.

Usage:
    python3 generate_test_vectors.py

Parameters:
    - Field: Goldilocks (p = 2^64 - 2^32 + 1)
    - State width: 12 field elements
    - Rate: 8 elements (positions 0..7)
    - Capacity: 4 elements (positions 8..11)
    - Digest: 4 elements (positions 0..3)
    - Rounds: 7
    - S-Box exponent: 7
"""

# Goldilocks prime field: p = 2^64 - 2^32 + 1
P = (1 << 64) - (1 << 32) + 1

# State layout constants
STATE_WIDTH = 12
RATE_START = 0
RATE_END = 8
RATE_WIDTH = RATE_END - RATE_START
CAPACITY_START = 8
CAPACITY_END = 12
DIGEST_START = 0
DIGEST_END = 4

# Number of rounds
NUM_ROUNDS = 7

# S-Box exponent and its inverse mod (p - 1)
ALPHA = 7
# INV_ALPHA = inverse of 7 mod (p - 1)
INV_ALPHA = 10540996611094048183

# MDS matrix (first row of the circulant matrix)
MDS_ROW = [7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8]

# Round constants ARK1 (first half of each round)
ARK1 = [
    [
        5789762306288267392, 6522564764413701783, 17809893479458208203, 107145243989736508,
        6388978042437517382, 15844067734406016715, 9975000513555218239, 3344984123768313364,
        9959189626657347191, 12960773468763563665, 9602914297752488475, 16657542370200465908,
    ],
    [
        12987190162843096997, 653957632802705281, 4441654670647621225, 4038207883745915761,
        5613464648874830118, 13222989726778338773, 3037761201230264149, 16683759727265180203,
        8337364536491240715, 3227397518293416448, 8110510111539674682, 2872078294163232137,
    ],
    [
        18072785500942327487, 6200974112677013481, 17682092219085884187, 10599526828986756440,
        975003873302957338, 8264241093196931281, 10065763900435475170, 2181131744534710197,
        6317303992309418647, 1401440938888741532, 8884468225181997494, 13066900325715521532,
    ],
    [
        5674685213610121970, 5759084860419474071, 13943282657648897737, 1352748651966375394,
        17110913224029905221, 1003883795902368422, 4141870621881018291, 8121410972417424656,
        14300518605864919529, 13712227150607670181, 17021852944633065291, 6252096473787587650,
    ],
    [
        4887609836208846458, 3027115137917284492, 9595098600469470675, 10528569829048484079,
        7864689113198939815, 17533723827845969040, 5781638039037710951, 17024078752430719006,
        109659393484013511, 7158933660534805869, 2955076958026921730, 7433723648458773977,
    ],
    [
        16308865189192447297, 11977192855656444890, 12532242556065780287, 14594890931430968898,
        7291784239689209784, 5514718540551361949, 10025733853830934803, 7293794580341021693,
        6728552937464861756, 6332385040983343262, 13277683694236792804, 2600778905124452676,
    ],
    [
        7123075680859040534, 1034205548717903090, 7717824418247931797, 3019070937878604058,
        11403792746066867460, 10280580802233112374, 337153209462421218, 13333398568519923717,
        3596153696935337464, 8104208463525993784, 14345062289456085693, 17036731477169661256,
    ],
]

# Round constants ARK2 (second half of each round)
ARK2 = [
    [
        6077062762357204287, 15277620170502011191, 5358738125714196705, 14233283787297595718,
        13792579614346651365, 11614812331536767105, 14871063686742261166, 10148237148793043499,
        4457428952329675767, 15590786458219172475, 10063319113072092615, 14200078843431360086,
    ],
    [
        6202948458916099932, 17690140365333231091, 3595001575307484651, 373995945117666487,
        1235734395091296013, 14172757457833931602, 707573103686350224, 15453217512188187135,
        219777875004506018, 17876696346199469008, 17731621626449383378, 2897136237748376248,
    ],
    [
        8023374565629191455, 15013690343205953430, 4485500052507912973, 12489737547229155153,
        9500452585969030576, 2054001340201038870, 12420704059284934186, 355990932618543755,
        9071225051243523860, 12766199826003448536, 9045979173463556963, 12934431667190679898,
    ],
    [
        18389244934624494276, 16731736864863925227, 4440209734760478192, 17208448209698888938,
        8739495587021565984, 17000774922218161967, 13533282547195532087, 525402848358706231,
        16987541523062161972, 5466806524462797102, 14512769585918244983, 10973956031244051118,
    ],
    [
        6982293561042362913, 14065426295947720331, 16451845770444974180, 7139138592091306727,
        9012006439959783127, 14619614108529063361, 1394813199588124371, 4635111139507788575,
        16217473952264203365, 10782018226466330683, 6844229992533662050, 7446486531695178711,
    ],
    [
        3736792340494631448, 577852220195055341, 6689998335515779805, 13886063479078013492,
        14358505101923202168, 7744142531772274164, 16135070735728404443, 12290902521256031137,
        12059913662657709804, 16456018495793751911, 4571485474751953524, 17200392109565783176,
    ],
    [
        17130398059294018733, 519782857322261988, 9625384390925085478, 1664893052631119222,
        7629576092524553570, 3485239601103661425, 9755891797164033838, 15218148195153269027,
        16460604813734957368, 9643968136937729763, 3611348709641382851, 18256379591337759196,
    ],
]


def mod_p(x):
    """Reduce x modulo P."""
    return x % P


def field_add(a, b):
    """Add two field elements."""
    return mod_p(a + b)


def field_mul(a, b):
    """Multiply two field elements."""
    return mod_p(a * b)


def field_pow(base, exp):
    """Exponentiate a field element."""
    return pow(base, exp, P)


def apply_mds(state):
    """Apply MDS matrix multiplication (circulant matrix)."""
    result = [0] * STATE_WIDTH
    for i in range(STATE_WIDTH):
        acc = 0
        for j in range(STATE_WIDTH):
            # circulant: row i has MDS_ROW shifted by i positions
            acc += state[j] * MDS_ROW[(j - i) % STATE_WIDTH]
        result[i] = mod_p(acc)
    return result


def apply_sbox(state):
    """Apply S-Box: x -> x^7."""
    return [field_pow(s, ALPHA) for s in state]


def apply_inv_sbox(state):
    """Apply inverse S-Box: x -> x^{1/7}."""
    return [field_pow(s, INV_ALPHA) for s in state]


def add_constants(state, constants):
    """Add round constants to the state."""
    return [field_add(state[i], constants[i]) for i in range(STATE_WIDTH)]


def apply_permutation(state):
    """Apply the RPO permutation (7 rounds)."""
    for r in range(NUM_ROUNDS):
        # First half of the round
        state = apply_mds(state)
        state = add_constants(state, ARK1[r])
        state = apply_sbox(state)

        # Second half of the round
        state = apply_mds(state)
        state = add_constants(state, ARK2[r])
        state = apply_inv_sbox(state)

    return state


def rpo_hash_elements(elements):
    """
    Hash a sequence of field elements using RPO with the new state layout.

    State layout: [RATE0(0..3), RATE1(4..7), CAPACITY(8..11)]
    Digest: state[0..3]
    """
    if len(elements) == 0:
        return [0, 0, 0, 0]

    # Initialize state to all zeros
    state = [0] * STATE_WIDTH

    # Set the first capacity element to len(elements) % RATE_WIDTH
    # This serves as domain separation
    state[CAPACITY_START] = len(elements) % RATE_WIDTH

    # Absorb elements into the rate portion
    i = 0
    for elem in elements:
        state[RATE_START + i] = elem
        i += 1
        if i == RATE_WIDTH:
            state = apply_permutation(state)
            i = 0

    # If there are remaining elements that haven't been permuted, pad with zeros and permute
    if i > 0:
        while i < RATE_WIDTH:
            state[RATE_START + i] = 0
            i += 1
        state = apply_permutation(state)

    # Return the digest (first 4 elements of the rate)
    return state[DIGEST_START:DIGEST_END]


def generate_test_vectors():
    """Generate 19 test vectors matching the Rust test: hash([0], [0,1], ..., [0..18])."""
    print("=" * 80)
    print("RPO Test Vectors (new state layout: [RATE0, RATE1, CAPACITY])")
    print("=" * 80)
    print()

    # Expected values from the Rust implementation
    expected = [
        [8563248028282119176, 14757918088501470722, 14042820149444308297, 7607140247535155355],
        [8762449007102993687, 4386081033660325954, 5000814629424193749, 8171580292230495897],
        [16710087681096729759, 10808706421914121430, 14661356949236585983, 5683478730832134441],
        [5309818427047650994, 17172251659920546244, 8288476618870804357, 18080473279382182941],
        [3647545403045515695, 3358383208908083302, 8797161010298072910, 2412100201132087248],
        [8409780526028662686, 214479528340808320, 13626616722984122219, 13991752159726061594],
        [4800410126693035096, 8293686005479024958, 16849389505608627981, 12129312715917897796],
        [5421234586123900205, 9738602082989433872, 7017816005734536787, 8635896173743411073],
        [11707446879505873182, 7588005580730590001, 4664404372972250366, 17613162115550587316],
        [6991094187713033844, 10140064581418506488, 1235093741254112241, 16755357411831959519],
        [18007834547781860956, 5262789089508245576, 4752286606024269423, 15626544383301396533],
        [5419895278045886802, 10747737918518643252, 14861255521757514163, 3291029997369465426],
        [16916426112258580265, 8714377345140065340, 14207246102129706649, 6226142825442954311],
        [7320977330193495928, 15630435616748408136, 10194509925259146809, 15938750299626487367],
        [9872217233988117092, 5336302253150565952, 9650742686075483437, 8725445618118634861],
        [12539853708112793207, 10831674032088582545, 11090804155187202889, 105068293543772992],
        [7287113073032114129, 6373434548664566745, 8097061424355177769, 14780666619112596652],
        [17147873541222871127, 17350918081193545524, 5785390176806607444, 12480094913955467088],
        [17273934282489765074, 8007352780590012415, 16690624932024962846, 8137543572359747206],
    ]

    all_match = True
    for i in range(19):
        elements = list(range(i + 1))  # [0], [0,1], [0,1,2], ..., [0..18]
        digest = rpo_hash_elements(elements)

        match = digest == expected[i]
        status = "OK" if match else "MISMATCH"

        if not match:
            all_match = False

        print(f"hash([0..{i}]) = {digest}")
        print(f"  expected   = {expected[i]}")
        print(f"  status     = {status}")
        print()

    print("=" * 80)
    if all_match:
        print("ALL 19 TEST VECTORS MATCH the Rust implementation.")
    else:
        print("SOME TEST VECTORS DO NOT MATCH!")
    print("=" * 80)

    return all_match


if __name__ == "__main__":
    success = generate_test_vectors()
    exit(0 if success else 1)
