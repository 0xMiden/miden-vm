// Copyright (c) 2022 Thomas Pornin. MIT license; see LICENSE in this directory.
use super::{curve::PointAffine, field::GFp5};

// ========================================================================
// For k = 40*j (j = 0 to 7), constant Gk[] is an array of 16 points in
// affine coordinates, with Gk[i] = (i+1)*(2^k)*G for the conventional
// generator point G.

pub(crate) const G0: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ),
        u: GFp5::from_u64_reduce(
            0xbfffffff40000001,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0xe53a14c4fa645562,
            0x60a03b3fcd006755,
            0xa8957cb5d9603510,
            0xe6e3a7d2ae140d1f,
            0x2067dd994d85be92,
        ),
        u: GFp5::from_u64_reduce(
            0x755f62aabb0862cc,
            0x01ec60924033842a,
            0x2c3c144f634bcc44,
            0xfc49506d49454da8,
            0x832fd0bd80667cb8,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0x3f1721a8b4bfe250,
            0x135784db6d866068,
            0xd30dd0109ffb1561,
            0x6dade466d752e9a2,
            0xacf8c6de680a22ce,
        ),
        u: GFp5::from_u64_reduce(
            0xe33b8641c16cb542,
            0x51df13bc6efd7d24,
            0xf47a6cbcb19b08f4,
            0xf4d93ddb98be42cd,
            0x2751d54472a53c2d,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0x3c414ce1f8aae143,
            0x7e727d66648035f2,
            0x6c3b9846d5f6b1ee,
            0xaf2022c48f8c580d,
            0xb513380b614cd936,
        ),
        u: GFp5::from_u64_reduce(
            0x31bfb83ae0b6f4dd,
            0x17d63bd29b7ed7a0,
            0xe5a9e36118531ac2,
            0xf38ebf5b61b910b7,
            0xff010361346c74e0,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0xfb7afb9f0749c52f,
            0x2f1b08170040d1c4,
            0x24c0e6f01acb4244,
            0xb940e85295a4bdd9,
            0x2f934b66cc631967,
        ),
        u: GFp5::from_u64_reduce(
            0x80916cd6733e31ad,
            0x670f5ae14e0cbd35,
            0x46e278d15f6e2188,
            0x8252b7241d444762,
            0x87d69bd8b06a37be,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0x99c65351b868d074,
            0x2b549abb45ae3b05,
            0xe6d26bbb7d6983c7,
            0xce8d90c97e847ffd,
            0x90490a2371237297,
        ),
        u: GFp5::from_u64_reduce(
            0xc5d015b9654827df,
            0xda4537a57ca4ce22,
            0x36c70dd003f9210e,
            0x41cb4479d87846e6,
            0xf142fd633cb37552,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0x4219c8aaa886a320,
            0xf821e49f695a9b94,
            0xbc7223437fa3f3ba,
            0x77d483207195d99f,
            0xbe37d76ad12515c5,
        ),
        u: GFp5::from_u64_reduce(
            0x2e8e911431f24635,
            0xc019a6c715b9a781,
            0x417911ca4f5c8c33,
            0x6eba314d3b0b4d84,
            0x8c6dc80b62684832,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0x37e2a1c7e50102c2,
            0xbcaea8e86e48319c,
            0x9f9654bf22e51108,
            0x8b0c420979d809a1,
            0xa659d6b7da77c522,
        ),
        u: GFp5::from_u64_reduce(
            0xc9aef44d3444f179,
            0x84fce8b4923cf2a1,
            0x2ac63df0ead62dfa,
            0x27af8adf6d3054c2,
            0x33fca2a42c8c4310,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0xdd27b15f06d34600,
            0x784d56f0c1d26c1f,
            0x06d180d9ad8c6590,
            0x5b62326a633f7a02,
            0xabe5478a46e4902c,
        ),
        u: GFp5::from_u64_reduce(
            0xb76f2d032ee42a38,
            0x00b792bf8263fb30,
            0xd5ba9b5f40896b2d,
            0x5db4a555e3dfa714,
            0x27a01c4cfcaf6622,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x7597f149cd01ffb1,
            0x21f55da1987f38ce,
            0xf94895e941d11482,
            0x6071f8478a6fb91a,
            0x8147478709a8ad5f,
        ),
        u: GFp5::from_u64_reduce(
            0x47c5fa108c16af99,
            0x29fc9d7035795ea7,
            0x064a742c800c7f1e,
            0xc42ab1d12867714f,
            0x237a1d635ad89d2c,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0x36f591486c28b83c,
            0x334a430d55cf5093,
            0x2872a90bfb945cbf,
            0x805e6320ae5b5820,
            0xf39aa3ff0f843a88,
        ),
        u: GFp5::from_u64_reduce(
            0x29d7f90c194ee89d,
            0x94e8bd911c76e114,
            0x2dfe8d94e8698b00,
            0x1b89fd3e133a360c,
            0xbf423dd058ba8584,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0xa0a63453b2520e76,
            0x154b9f3b3ded29a2,
            0x68a11c1528013c8f,
            0x903b80a6f09ae901,
            0x940a7401f7737c15,
        ),
        u: GFp5::from_u64_reduce(
            0xe7801dea8ae5c94d,
            0x9ca6a99fc677b56d,
            0x99a02f2c85b98888,
            0xd6ef067b29f73b09,
            0xbae7df0908f3326c,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0x9b529bdd12ba8168,
            0x315948d3e2c24095,
            0x4a32aad7f2bd5d71,
            0x3ea68814c835f7ac,
            0x3693dc2bfe7a0305,
        ),
        u: GFp5::from_u64_reduce(
            0x4b3d8724805d3595,
            0x02d5d1434e2b7fa0,
            0x5433b329f514b8d9,
            0xe0b27774e7fd8ad5,
            0x39740438fa4de60d,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0xb70b88550bcdc40a,
            0x79ce838fd1512fc2,
            0xf2d254fd78b4176a,
            0xd21d143bd0c3d6e8,
            0xd7586f2424cd8a89,
        ),
        u: GFp5::from_u64_reduce(
            0x0e7078e4323a9af6,
            0x808bb98be0705106,
            0x29802c432fd1b88f,
            0xfb97d7787351836f,
            0xad55a82a983e13be,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0xf5ddae987fe1a8b7,
            0xc72a5894cae32911,
            0x329407834833459f,
            0x47c4368abadafc42,
            0x04175d3818d989ba,
        ),
        u: GFp5::from_u64_reduce(
            0x68927fc54de30bb1,
            0xcbc1374ac68435d3,
            0x0ae217db1a860a3d,
            0x49486982ed44b94c,
            0xc7f1d337344580b9,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0x787a277b60dff343,
            0x6b93cdcc42380c6f,
            0xe359042b24517973,
            0x67599c1234ca257e,
            0x5f334a5914c62fff,
        ),
        u: GFp5::from_u64_reduce(
            0x8642adfd967547f1,
            0x48d8168e1347c6db,
            0x321fa2d8ef93d21f,
            0xffddfaa10ed7545d,
            0x31195bcbf821882e,
        ),
    },
];

pub(crate) const G40: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0x611a5359fcf0a4bf,
            0x12370f87b8c02b88,
            0x1b4c636c579f5ace,
            0xac89fbcf88f6c0a9,
            0x71a4e222268d96e3,
        ),
        u: GFp5::from_u64_reduce(
            0x87b686e43f300726,
            0xb2051f0c83df5ecd,
            0x732bfaacd02e6493,
            0x8b93dc17b6d61a39,
            0x84b2cefec769cbe1,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0xb0a217943742e147,
            0xa294deaa61794f12,
            0x9c3cd78d82554027,
            0x44a5e5721ff637af,
            0x94222a04b9b09cfc,
        ),
        u: GFp5::from_u64_reduce(
            0xc1da484eea20e61b,
            0x87839986d2c0c417,
            0x536726f207af8ae9,
            0x0ce2d8784c4c06bd,
            0xf38780bccce10933,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0x141d1dc8eb53d8f2,
            0x119b541dacdb7e25,
            0x00f4e51c4122258a,
            0x070d3841b7c30d81,
            0xcfb2f9e418bf898a,
        ),
        u: GFp5::from_u64_reduce(
            0xadbcfa8d2cd4bd91,
            0x196805299fc754a5,
            0x730c5bd275bd1f10,
            0x60a2f4a66ecaf807,
            0x45c489829d03437c,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0x68ae5601eac10b82,
            0xb68d5a1d87381951,
            0xb4f2849ee7337b90,
            0xf45afe402b9f2354,
            0x38931da82c2ab7ad,
        ),
        u: GFp5::from_u64_reduce(
            0xe4a064dceda49780,
            0x65e6a29dbef8a1dd,
            0xa4131b06679d9e21,
            0xdbce53bce947882d,
            0x7466b758c333eaad,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0x6089b3824d410c77,
            0x8fd29fde1a3d8d78,
            0x167564b36436bbba,
            0xea5a00784d95e6db,
            0x452719f72fd61c13,
        ),
        u: GFp5::from_u64_reduce(
            0xbdf5b501aa8cc54c,
            0xf912b0b754da2189,
            0x63127d35d8f1d3d9,
            0xca1fb0958f64d4d4,
            0x394442a46629c061,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0x0b1c9b08197ab917,
            0x99363de503ccc6dc,
            0x14595d2ef0327468,
            0x7431486e378fd529,
            0x96eb7445b9fb8e96,
        ),
        u: GFp5::from_u64_reduce(
            0x4146fc8e3963fc23,
            0xdedcfdc1fda931b6,
            0x7419e78eda5eea0a,
            0xaaffc23f3059eb35,
            0x219031a52bc58cc8,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0xadbab9d522bd3724,
            0xfd7d5eb6be3578b6,
            0x3c70c562176c61fe,
            0xe2aada2e4890ae6c,
            0x6d1743861bc53911,
        ),
        u: GFp5::from_u64_reduce(
            0xa8e2a8f79fe34ea2,
            0x13d0507bdc9a9e5a,
            0x2fe75772503cedc2,
            0x3fc74c6c8b738b8e,
            0x4e38e48c25ceeb31,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0x615eb8e1f0c83e68,
            0xcb81875e029323c6,
            0x65286de9000965e7,
            0x33cffdae8bc911a6,
            0xb397069155631d82,
        ),
        u: GFp5::from_u64_reduce(
            0x52bde21f53dbf866,
            0x6ba936c397782d19,
            0xf6636580fc790962,
            0x4dd42818f1555407,
            0x8cfbee063aeaed35,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0x8606edc9d5e9113e,
            0x182007e52efe27c2,
            0x2def1cf3ff3d0e56,
            0x48c88c73dd199cd7,
            0x9a0633769d643c8e,
        ),
        u: GFp5::from_u64_reduce(
            0x8d3adab2eb7c1ce5,
            0xedffacf33e5ef7ac,
            0xe5c9256d106262d2,
            0x58f2a9b6bcbcfde6,
            0x06342e1e589a293f,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x1bc27d027a958173,
            0x6ee3bd06429418fe,
            0xc0c81c8d10d4357f,
            0x2f316bbf8ad1914c,
            0xf4f1d345afaadf4a,
        ),
        u: GFp5::from_u64_reduce(
            0x7d0dbc22d7972122,
            0x86c7fa7ce07aa8d6,
            0x4821b6a52390d398,
            0xcb3c24236f5242fd,
            0x46a8a25cda5d4331,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0x3c6b69452df20da5,
            0xa16382da71339ff0,
            0x0734ed8af2ff492e,
            0xf231730c6f123884,
            0x6fc56d7052cbd46a,
        ),
        u: GFp5::from_u64_reduce(
            0xe179905de5b7e0c4,
            0xb8ddc95767b72473,
            0xb78dd85b25eebb13,
            0xdbb1f2e1b16d69af,
            0x8d29614950f6815f,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0x7799965532068142,
            0x28b108bb3c43e88c,
            0xc2db5f750355bea8,
            0x7681956bf5aa1319,
            0x721e95d6212552e9,
        ),
        u: GFp5::from_u64_reduce(
            0x1d6543850c7b0929,
            0xec2a26a51b23b809,
            0x350ca7888d6d1bb6,
            0xf9f9e18245c88ec2,
            0xc9fe9387c28fb541,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0xc3bcc4f02eac0c83,
            0x40d4cc7ad230af3b,
            0xca8cf9f2155561e1,
            0xaa99a9ad55042ab3,
            0x99cfb2ea5c310f59,
        ),
        u: GFp5::from_u64_reduce(
            0xb4982a468fa68497,
            0x5865337073a89564,
            0xbe56c3bfcb41f3de,
            0x0b8ef2f8e362697e,
            0x27551ded6c8b2f69,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0xf465cd82f6782e19,
            0x7c27481748425d26,
            0xc31289ff743e003b,
            0x5db208b4b28fbd05,
            0x92d7b2a86701447b,
        ),
        u: GFp5::from_u64_reduce(
            0xe976dff362834259,
            0x6192bcd9481de3b8,
            0x1940fe2ed27a5d23,
            0x14809df701e212e2,
            0x2a7a9e074d9c514e,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0xe35c62cf3f65d6ef,
            0xf098aa0fc2f2329c,
            0x8eb38143a4a67389,
            0x7b8da3ddc3b09aa7,
            0x8b499f766bf7df6f,
        ),
        u: GFp5::from_u64_reduce(
            0x0d9c66b7d75aa0ba,
            0x7a711cacc51f2cdd,
            0x114f33e3793d5e1e,
            0x6fb4fe75d138043f,
            0x4fdd0f0e91eae708,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0x4284bdeab4b3c711,
            0x8f76c066935bd65f,
            0x3ca785b64d9ca29f,
            0x734fb37b0d88e69b,
            0xa615cd2231c23f7f,
        ),
        u: GFp5::from_u64_reduce(
            0xf40ea9d64bb8db38,
            0x988ba6a1e479bad6,
            0x3b728b804e9fb190,
            0x93151a8a49c7f10d,
            0xb878eb1aff80baa4,
        ),
    },
];

pub(crate) const G80: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0xbff791ca85bc028c,
            0xf9fb2901ac55ca28,
            0x12104ec08515e4d1,
            0x7ed4b2e7eeb96ebd,
            0x3e86614ea1297f5f,
        ),
        u: GFp5::from_u64_reduce(
            0x66234f2978c62e9a,
            0xe797bc8963f28598,
            0x3d0fedc88533efa9,
            0x4928c92b69fa6381,
            0xa1b5cc952764418d,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0x981134c4be7edf34,
            0xd40a50866d224ac8,
            0xe6def6024a2a53c2,
            0x01ef1ce227edafc2,
            0xcef67cbf79abfb65,
        ),
        u: GFp5::from_u64_reduce(
            0x61341049363d9806,
            0x08de86f9a1d453b4,
            0xf0b229c09a150c3c,
            0x9a6b56c97677b746,
            0x609bef57eda9c360,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0x174a2490b64aa7d7,
            0x90ed1c03be0a1e10,
            0xda36bbe81409e8ad,
            0x067986860f1796aa,
            0x1337390b4d19d913,
        ),
        u: GFp5::from_u64_reduce(
            0x6dcbdc9d8b6ffcf1,
            0x7d047179b73acfa1,
            0x7a85aa3fc5afcefe,
            0xb1b14799ab054684,
            0x47bb870dd0b97bba,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0x862e7baef49c57be,
            0x16763810a8e92363,
            0xdb5d6e0a97f30c0b,
            0xc95a211538bfd9c5,
            0x74954f9da117998e,
        ),
        u: GFp5::from_u64_reduce(
            0x1cbc9ccd138e89c8,
            0x56ba4d9517bdf76a,
            0x4875abc85e225a46,
            0xb20eac89a5de3234,
            0x5e583f59e343d970,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0x0883bcd672d03a45,
            0xbf9da799e22b0280,
            0x44844bd86742b4f4,
            0x2a4187be0a3291e4,
            0x93ef3d4d5b9fef68,
        ),
        u: GFp5::from_u64_reduce(
            0x9c628a98c225201a,
            0xc3e274c30e326b21,
            0xd20919ec01919cd1,
            0x708be53371bb1513,
            0x2cf0872abfc8de56,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0x32b323fde01834e5,
            0xeb7d58926002d7a5,
            0x311976f6b1de8c50,
            0x53f0d01bce04fc3b,
            0xb83c631fb53e6835,
        ),
        u: GFp5::from_u64_reduce(
            0xd49d9b793d4c47c3,
            0x05e243e0adc4c074,
            0x87cf12ffb6194074,
            0x0194c81951adbce2,
            0xf2574b54f7601426,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0x4d60adbd2cf65dc1,
            0x1e61b2df00932777,
            0x17669d53561d21b9,
            0x5d7dbf43e4da3098,
            0xf1f1c35adba8c435,
        ),
        u: GFp5::from_u64_reduce(
            0x61f2bd2c307f98d0,
            0xe5e6acc9f0b7c41d,
            0xb2de8fb853425f4a,
            0xc80f67cf92860da9,
            0x0feb48f9807e881f,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0xd94ccfebfe7376a8,
            0x1f69b506843a9fb5,
            0x25af59d5ac2d3e6e,
            0xa59bdf1cddf32601,
            0xf6994d2e8166a9ed,
        ),
        u: GFp5::from_u64_reduce(
            0xe8646785e9539a66,
            0x8458539c65a3863b,
            0xad8a7e5acc5827c1,
            0x09c7a04f5884ff56,
            0xca3f64d3d9836222,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0xbe252f638d10a319,
            0xa01d12686c403f4b,
            0xfe05fe819ec8dc6d,
            0xebcade7de489a748,
            0x733123271e24bc37,
        ),
        u: GFp5::from_u64_reduce(
            0xb3ab56ce983235e8,
            0xde6fdb91d66a50ea,
            0xc86eab8154e9f48c,
            0x71dc9d64b9f0db6d,
            0xb49651b0086141ed,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x7c97a1b3d2bcf519,
            0x745e8a6d42e74374,
            0x59a5c1467b27ce5e,
            0x91b9e0010a0f5e0a,
            0x7116292d5bf4db68,
        ),
        u: GFp5::from_u64_reduce(
            0x08ffa357f0044133,
            0x1c01e00b47b320b5,
            0x997ab99060da5999,
            0xee4d13b68b36e2f8,
            0x0a0052f08b6d6a49,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0x0768481a730111e7,
            0x7ebfba3f4b985e9b,
            0x5a29abf499ee8220,
            0x465e398a5e5d9f80,
            0x8b24e98561f1e7b6,
        ),
        u: GFp5::from_u64_reduce(
            0xf03f941053c2f189,
            0xaf15b126f1dd2362,
            0xe0c1f9661069145c,
            0x70ac53657d214da1,
            0xe8cb1591772591d3,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0x7c9805e37afb8fda,
            0x7ec6e5aec3944fd6,
            0x799ad8712625a151,
            0xccf07eee9356056f,
            0x8000967388385792,
        ),
        u: GFp5::from_u64_reduce(
            0xd3e9e6243aad543b,
            0xa593bc22a29b572d,
            0x1b7927e3cffd9e34,
            0x8bec6e12a8095b62,
            0x3f79034163a87374,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0xb2703bf5809085b7,
            0xa1a318c3972a7206,
            0xf198687adb77a5ee,
            0x521d68c0984aaa30,
            0x0e87e4af29f07f30,
        ),
        u: GFp5::from_u64_reduce(
            0x00d595a13dc09a16,
            0x1718e2432ce9aa64,
            0x6232c6a30d7280c9,
            0xc1ee0841ad6808b2,
            0x9d11ff978aaa9dd1,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0xf234ca90dc099c7d,
            0x5f852be145ba1d9c,
            0x81216f4f65d6c3fb,
            0x0d9eee31a8a67e94,
            0x98fdf4a20afb5398,
        ),
        u: GFp5::from_u64_reduce(
            0x24347a34b17d37e6,
            0x27bb083aa277ac09,
            0x7dbaef7b797e2ce5,
            0xe9d42158a195e722,
            0x00c334027c0d49b3,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0x655df87f3af6cc59,
            0xaf94bd95765d3477,
            0xa7045ce70f44e1fc,
            0xc9ba067f552c2bbc,
            0xe43c604d34512222,
        ),
        u: GFp5::from_u64_reduce(
            0xc27ad2f5d6671b2c,
            0xb9378f2c40637be7,
            0xca0c8a5255f697ce,
            0x8be0e122dc2e05a7,
            0xb8cf62f86bf9a6fa,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0x1cc5baa51da2d312,
            0xc0f23b1b0fe4ed2a,
            0x5b88de0a0b959a46,
            0xb0b9a35abed716c3,
            0xc9536a8eb50c5d89,
        ),
        u: GFp5::from_u64_reduce(
            0x0015f3561509a9bc,
            0x47fc4bc52d6bb76b,
            0x1d1a0eea38a66200,
            0x324d88263ae0b8e2,
            0xdbc3d405c7da217b,
        ),
    },
];

pub(crate) const G120: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0x81dfc7a7a5475cbd,
            0x56113bcfac979210,
            0xf33847958d1d8345,
            0xfc3047b32e95a30b,
            0x9ff367e17679cf4e,
        ),
        u: GFp5::from_u64_reduce(
            0xd590cf0ca8d4761e,
            0xf1d3810d25c0b2c6,
            0xd90967f9bfe553bf,
            0xd0bc6d8c9e227371,
            0x6e275038fa572267,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0x05e572ba66b15b39,
            0xbba9c5154ebeb103,
            0xae8e2a206c070cfb,
            0xd6ccff9306078ab9,
            0x2b1f8d1112efd844,
        ),
        u: GFp5::from_u64_reduce(
            0x01effe47ec31e510,
            0xb511ee2b390b0ec8,
            0xca2f7cda89514ad1,
            0x1f1c5db055753591,
            0xdb6827dfb0f409f3,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0xc918cefc9cd298a2,
            0x7f9103abcb08e989,
            0x47d00af024caf0b5,
            0xc9783b10ba49607e,
            0xedb25a9081bb9cf2,
        ),
        u: GFp5::from_u64_reduce(
            0x935a4020350e5beb,
            0xd670c08a7082f4a0,
            0x0107ac6f82f699b7,
            0x620d1c3b355a0565,
            0x1a7bde0aecf72f81,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0xc47c9cd50b313694,
            0x9702d00b57f7cc7d,
            0x88a0c30d160a23ba,
            0x0446898927d7d998,
            0x1f57a65f0af07cc6,
        ),
        u: GFp5::from_u64_reduce(
            0x8d67db1d9c30123b,
            0x2de54dc1702f4889,
            0xd2da0ed1e2f9b6f3,
            0x15229a59d9a0f308,
            0x8f6d90ea4a987a4a,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0x60fc681c2040df2b,
            0x5ddb0b69f69a2c78,
            0xb04189024b566274,
            0x971dd29d44e756a0,
            0xca1b53ddfafbb17c,
        ),
        u: GFp5::from_u64_reduce(
            0xa83cdc13589012a5,
            0xf9361d69cd5d929a,
            0x130724e183727f72,
            0x61d732b0b0c613f1,
            0xc4b677ce6d45bb1d,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0x9a874d914401394f,
            0x1b10689a9f8dbcd3,
            0xda1edf2cbf452064,
            0x2f3f0ca1dfb9d39c,
            0x49935367cde51d51,
        ),
        u: GFp5::from_u64_reduce(
            0x32502febf9fc4762,
            0x648fc03b7084325a,
            0x0c41a62661cc2bb8,
            0x43dd5654e0ec867a,
            0x5121d65e62af2d83,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0xf6bcd91b9d229c4f,
            0x1ed90b399ce1f26f,
            0xc69bf32330251380,
            0x54882b5c8b4b746b,
            0xb7e5714d168bf813,
        ),
        u: GFp5::from_u64_reduce(
            0xbcadeefa2b9b265d,
            0x4a324d10dd8950b4,
            0xddae64902599551e,
            0xf3d542fa995ae725,
            0x3e4c6ebd817c001d,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0xfab7b11c9f5da1d2,
            0xf923cfbc1e20152d,
            0x5fb28b0bedfaad83,
            0x48de620dbf3d5831,
            0x4cf82e5ae1d1b588,
        ),
        u: GFp5::from_u64_reduce(
            0xbd1f6c5b2df2fdce,
            0xe275428000b3cfb7,
            0xf32b9605ca11f251,
            0x2915e5380c54d3fb,
            0x80157d2979db3056,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0x11f8fd3613eb3394,
            0x26fd38fde73f91e2,
            0xea33d1e4655af9ee,
            0x05c24e7b239b8eaf,
            0x7b46bb6a9e90b5c3,
        ),
        u: GFp5::from_u64_reduce(
            0xc376ec1f984898e3,
            0x1432c1c994f0c08c,
            0x6316ddcf376d7cf7,
            0x2ddaa603e9b5bf50,
            0x24518afd5f7c2860,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x5716e9a9a5082f96,
            0x2f0e8bad605d068a,
            0xef5d32fda8d82584,
            0xc42304afbd7d871c,
            0x36687e044dee4634,
        ),
        u: GFp5::from_u64_reduce(
            0x69ddbce5a4ed87f4,
            0x526ec1af1567153b,
            0x7e5c060d48ce5c40,
            0xbbfec2c8fd487cc1,
            0x8ea69a07f739eabc,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0xa16992d30a7af7d9,
            0xaf24506003383737,
            0x011ae62187aa31d0,
            0xf8b24e6fc064709e,
            0x50dcb633172f23ed,
        ),
        u: GFp5::from_u64_reduce(
            0x25f89f2718eb46c2,
            0xc7f267222a19a771,
            0x906877203579dfba,
            0x28f5f954a16530b2,
            0xec51c1ad7fc50ea1,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0x8a9efbfad6fe2b7b,
            0x05f489aa4cb43222,
            0x6b0644743682456e,
            0xcdfe708173216b70,
            0x1f4602ce2ee4c17c,
        ),
        u: GFp5::from_u64_reduce(
            0xee8f4d0979d37a3c,
            0xbfa35bc84142f9de,
            0x4077ed5e3f53b5e1,
            0x8fc7e38e062ab1f7,
            0xb475144bb33472d7,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0x4b554eb298e6827b,
            0x520957e0c44f2929,
            0xa70073ff75531c87,
            0xc3b0cbf9f188fc9e,
            0x280d47fd2d499a8a,
        ),
        u: GFp5::from_u64_reduce(
            0xb35f4c19929b3cf0,
            0x59a153f47d6d83da,
            0x771aff712a96cbc2,
            0x828189393af72e26,
            0x39d179af302624ee,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0xc2f8e5c058865246,
            0x8ab1f6998ca70abc,
            0xe6673cf650d2b916,
            0x7a33c8a0d27f468b,
            0x07900417775ed00b,
        ),
        u: GFp5::from_u64_reduce(
            0xfc5b21f6c152f2aa,
            0xa064de2b87ec6b74,
            0x6c06c835ac6a1839,
            0xa0c0ec16e089f39b,
            0x612d331e37583569,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0x0b4c5ae4dfb02d59,
            0x01928464b2e04ece,
            0x31509cbc754df607,
            0x4f6b3c63839468b7,
            0xbbd9267b5b575941,
        ),
        u: GFp5::from_u64_reduce(
            0x94be85f938b56fa7,
            0x139794d63c1aa09d,
            0x1dd665b970682c0c,
            0xcc7e05810839afbd,
            0xbd5552d96f644dc1,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0xe4c0092e44a2cd56,
            0x8640177369c89fb1,
            0x6bb2efb2d47bef55,
            0xc3daf4226cb841ee,
            0xc496cd80f48fc705,
        ),
        u: GFp5::from_u64_reduce(
            0xe0d4a4d054567841,
            0xdaeecd5f3824b100,
            0x7921f0ac2e9068a8,
            0xc6fa0d80661c7931,
            0x5f583deb723d2502,
        ),
    },
];

pub(crate) const G160: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0x3830ee0b997a7060,
            0x7497cabd07057dc0,
            0x75927e746d00183e,
            0x9c6dadcc11deaeac,
            0x9f66177b8921cd13,
        ),
        u: GFp5::from_u64_reduce(
            0x8a86d127d7936bef,
            0xe5149e6285479398,
            0x87f259b34e5bd418,
            0xc9bef27d34416090,
            0xe8f755d40d6865ba,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0xe5319bbc868a2d7b,
            0x2725c72d33f3817d,
            0xc9e0de1b121d2edf,
            0x6ff67e5d3efd38a3,
            0x4cfd98fa2fb85bf2,
        ),
        u: GFp5::from_u64_reduce(
            0xb696aed1dd180d3f,
            0xc3659521aad5eca1,
            0x32d71817413b6dc1,
            0x7295cb868ccfa40c,
            0x6f61da7362ea8310,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0x63e82230de1a29ee,
            0x5a4edc24826d47c8,
            0x794f1e3cc2f9c121,
            0x45d55698bcee11dc,
            0x146bd13724fbd24d,
        ),
        u: GFp5::from_u64_reduce(
            0xdfd1f5f4f742a5e5,
            0xf51e15e97a61f13f,
            0x4b4dd1444e59f27d,
            0xb0118cdbf0436fcb,
            0xa25feeda6dc43b5e,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0xd7abe1664b48916d,
            0x52f58a2ec038e24b,
            0xf468611e6a5cd3d0,
            0x19f2cedb6fd320e2,
            0x03a45c530e0e481e,
        ),
        u: GFp5::from_u64_reduce(
            0xe7058edffc45e01c,
            0x229820847ca245ff,
            0xb4571ce63e1fe7cd,
            0xfad16d9cca297c82,
            0xe0936814b7a3faa2,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0xc88e81be7cb8be13,
            0x253980df689aa3b3,
            0xdb0ee9b47b609458,
            0x89937595bcf05abf,
            0xed186ab8bca3cfa8,
        ),
        u: GFp5::from_u64_reduce(
            0xb4a0638b7f06669a,
            0xfbbf589d6fcedcbe,
            0x473dddc6df96c85a,
            0x0811c5874613bced,
            0x94c84d7d9d2209d2,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0x18191fa200fcf6af,
            0x2302a5f56cdd8d5e,
            0x75d51cee7508100a,
            0x2a7cb1bbcc4b6e82,
            0x68ed086b8efe0952,
        ),
        u: GFp5::from_u64_reduce(
            0x238679b861a2b71e,
            0x72e5947423e98442,
            0x825e4fb253b3bee7,
            0xd59828c79d39170d,
            0xd64be0c2d3c4bddf,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0x906be97e5bc88259,
            0xa9d29deb5bfa6301,
            0x5794a30dda67c7af,
            0x391573041251e9da,
            0xe958fca20e602c8e,
        ),
        u: GFp5::from_u64_reduce(
            0x2bf49c6d28b7cd14,
            0x2ed045f27ac1ac99,
            0xb7b07e480d6e4980,
            0xdb7ded6782e1aef3,
            0x6f0c4fbe7c1c5fc0,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0xfc44982da86bfa06,
            0x64099395cf0d88b6,
            0xcd1d2382a6c43a54,
            0x1bb3f627b1b99008,
            0xd0e9ddea10328819,
        ),
        u: GFp5::from_u64_reduce(
            0xda17d468f1de5c01,
            0x78ef4b4d0ed0be22,
            0xe11770286753c974,
            0x0368bf12362bf72c,
            0x404dee08cfddfd8a,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0x198e62045db35a74,
            0xfc033f301db930cc,
            0x628e7dba48cdd07f,
            0xf1c019df9777f7c9,
            0xdc4526d93675652d,
        ),
        u: GFp5::from_u64_reduce(
            0xcf5037db2206a383,
            0x147aa2b70ffe8ca7,
            0xdebe043528f23b85,
            0xcf27f1ac633aa891,
            0x9e1e0153d9c060a8,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x98e0c0ccab0764e4,
            0x8f97708426132a48,
            0xd5e74bde6bec4714,
            0x349746192fa1cb98,
            0x8f525a63d2a9223a,
        ),
        u: GFp5::from_u64_reduce(
            0x146aab875512fe13,
            0x3dc2670a500de2b6,
            0x1bbe14227a54e1ff,
            0x19d792e2356253aa,
            0x8882dd5b5969304d,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0x5d6c8679525e09f1,
            0x870a9337817cac33,
            0xc882b79142b218c1,
            0xa9c42826b65ce8a2,
            0x477783199f3b842f,
        ),
        u: GFp5::from_u64_reduce(
            0xb8a2c0757677c713,
            0x851acdffd11bb41a,
            0x62b97cd3a35dc135,
            0xa3b31a08de1fbfac,
            0xd752d76988ddd12d,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0xe0e90c6ed39b654c,
            0x67a39af711058681,
            0x0d3daef3081904f3,
            0xd3c338bada40006d,
            0xb33f7393564ec4d1,
        ),
        u: GFp5::from_u64_reduce(
            0x987708704eb02d95,
            0x0cc04ab0a501765e,
            0x943216be72a6dfd7,
            0x7f51ad2a5d248721,
            0x61cc888bebcffb80,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0x4caa65a18b975968,
            0xb495513833e42713,
            0x78c113f1379958f1,
            0x697ca2048d326dd5,
            0xe963a1404d90cb8c,
        ),
        u: GFp5::from_u64_reduce(
            0xf04ba0466834991c,
            0x7b912d4eb5f31927,
            0x99c6e4e89612f6e6,
            0xa91f4bc177c2176a,
            0x94a885b9b08b2d5f,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0x56f0d795c32cbe87,
            0x931f870df82c1525,
            0xcb6abb5ddbc8e3a5,
            0x3dbf89d464c2312f,
            0xd48bf8e7b291816e,
        ),
        u: GFp5::from_u64_reduce(
            0x276c69a01726373f,
            0x5107374917ab3272,
            0x773dd2a5cc82b6f8,
            0x991989e9601107ec,
            0x944e8035a63d7eaf,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0xff673761a7450b49,
            0x4ae007faf082e23f,
            0x3c8c3e05eeb3f6a5,
            0x35ff9c11cc2c3ded,
            0x62bc066a6e5c6720,
        ),
        u: GFp5::from_u64_reduce(
            0x372c34d7004a8efd,
            0xef289159a6db7c6c,
            0x29fa45e3fa32c323,
            0xa6de74555d6f4465,
            0xe68b116a5aa1bf61,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0xe9ee4bd0ece528fc,
            0xcd31c6fdd181b556,
            0x25e8f951b5c13f88,
            0x4f1d865943228fb1,
            0xe526f967a8bdcce8,
        ),
        u: GFp5::from_u64_reduce(
            0xd8fd6271ded8e77a,
            0x8675f320d3750ceb,
            0xbd5fe217a8a07a18,
            0xa40203c0b4fccd19,
            0x4ae32049567a9b8b,
        ),
    },
];

pub(crate) const G200: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0xe616a89f4a4c3ddc,
            0x40965d57246a34fd,
            0x1a16eb3efdfb7930,
            0x6371f59ab8442179,
            0x8b287ef89765e37c,
        ),
        u: GFp5::from_u64_reduce(
            0xcb9de30898259cd1,
            0x70e50403c409de58,
            0x175767980e9cb777,
            0x2ae405d1b885a713,
            0x46883205f6461f73,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0xb383fc6c08553929,
            0xbdf89c37968ef761,
            0x7d1f44ee38c66d8b,
            0xfad5feb55710565d,
            0x8bb6ac3e11119ec2,
        ),
        u: GFp5::from_u64_reduce(
            0x1a3ff0e69015297b,
            0x83118325e370e206,
            0x95a5c6611f30ec5f,
            0xd1b9ab1269da3c74,
            0x75d202969b61d2ff,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0x371cf61d1b6bee4f,
            0xa46896d9a0d6d340,
            0x64a4ec7ed6f98b69,
            0x27619fe45f8042c9,
            0x07b2bba45d8b4da0,
        ),
        u: GFp5::from_u64_reduce(
            0x1fb1647224994736,
            0x40ee9c769bd173f1,
            0x62091ae7a020f159,
            0x11f4f4ac42aaf6db,
            0x3935e9faf93174ab,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0xf0c24c0829d03884,
            0x77e44895d7601409,
            0xdb85941edf473dfa,
            0xf91cdacadb1c6ea9,
            0xd3d067dc0eccd4c0,
        ),
        u: GFp5::from_u64_reduce(
            0x46dffbed29fbd34f,
            0x3794971420f3f342,
            0xbb34444abecc2b7a,
            0x13fab655f99c4328,
            0x287805e5b39c7a54,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0x600fe70a8b05b252,
            0x42d935d34d536cff,
            0xc72035e7c95b3354,
            0xe57cc01bd27b29f6,
            0x732714762a107aa3,
        ),
        u: GFp5::from_u64_reduce(
            0x3144661d70681fa1,
            0x51e1542cff2c0ce8,
            0xdc665eb7401e02bc,
            0x3e5eba71bd571963,
            0x09b22663205e1fba,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0xe163d75c513e0ccc,
            0x5518cabc28ddc4f7,
            0xe9961d5370bc5b65,
            0xef742bae495ac058,
            0x9b395f6a4f9b6a26,
        ),
        u: GFp5::from_u64_reduce(
            0x3ba66ffa8ead89eb,
            0x63c5e48a245d7aa8,
            0x82b6acefea7e4d76,
            0xc9a9359d54a4dd0f,
            0x768aca943ddeceec,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0xd661dae6d3dd9f89,
            0x4c710b466e774311,
            0xe4c95e255e5683a8,
            0xb78137c990e22f80,
            0x2bda022583dafb0a,
        ),
        u: GFp5::from_u64_reduce(
            0x4838e9014dea3d70,
            0xbae8c676f3afca06,
            0xee93be162c1af743,
            0xfd3883ea55c9acf9,
            0xd4b0c1daf01c9d23,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0x93657b3895954257,
            0xedd022ffbe81d10e,
            0x8142c0945c90101c,
            0x82033657eb7353f8,
            0x76bc6646bb3716a6,
        ),
        u: GFp5::from_u64_reduce(
            0x6a5e0a4db04ed6f9,
            0xe1429e1f0979a5dd,
            0x5b747016e1ed1833,
            0xcae934c07525c37f,
            0x5e3424ade845e49b,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0x09ff77563a30b446,
            0x07bf53470594de2a,
            0x4ce72c200f8d6e9b,
            0xe52273bc7ed7ca35,
            0x9033849a19000af4,
        ),
        u: GFp5::from_u64_reduce(
            0xb933301371ff9291,
            0xbb910d3069ae5106,
            0x5e0d307fe9f0f779,
            0xcd9a0eb95dddcef1,
            0x19178a0f43ae2c1e,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x7623c4be201756e1,
            0xbd2f0633aec30a94,
            0xd337c303193bb7ae,
            0x572cfbfed1a8acf2,
            0xb01c34b6ea7e1ef3,
        ),
        u: GFp5::from_u64_reduce(
            0xd380c1fc9d68ff85,
            0xbbb8b9f9cf5182a2,
            0x0557d0e40bba2fdf,
            0xecb278ad146404f7,
            0x87ffd86e47af23aa,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0xe40edfe66ba15a89,
            0x0e9e3e2f33526d04,
            0x4ba5c6033a38b887,
            0x3842c01d32ab77cc,
            0x28e5de9e77245d22,
        ),
        u: GFp5::from_u64_reduce(
            0xf8cfa6bb96dd0801,
            0xf133e8ad176bca29,
            0x9c1eab583453e8f8,
            0xbec6adfb1a8d8e97,
            0xae7635a4af1c877c,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0xff384ed70e2e92b1,
            0xc1b07c818fe7707f,
            0xceb40739bd2e6aa8,
            0x4a03a62921d5c51c,
            0x8bd601a17d2f7cb4,
        ),
        u: GFp5::from_u64_reduce(
            0x727ef2e2653167b4,
            0x4fd64c260f9a4fd8,
            0x3297687634294c9c,
            0xb307544d393dc724,
            0xea542c84cb669681,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0x156fc875bdcdfeba,
            0x092fcff076042ffe,
            0xffafca9a76a95eb9,
            0x2d0c797173c306f9,
            0x485198ef86718f90,
        ),
        u: GFp5::from_u64_reduce(
            0x3de83246eba16461,
            0x2fe484942cb74fa7,
            0xee8d2538886d8b97,
            0xe7b3cfe2d407e1a4,
            0x09e243332adb265d,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0x57586a9e04a0dd6e,
            0x0eb1ccc8cd18f018,
            0x4a1d82a3b69c217d,
            0x4635fb578fc490af,
            0x30f103c0d76e17b9,
        ),
        u: GFp5::from_u64_reduce(
            0x9ad7880e8116b808,
            0xb4388460dc70697c,
            0x3135215930d6569f,
            0xa38fb7775b6f9168,
            0x8c27888e47141129,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0xa36967535666430f,
            0x0b10f73be3d3b04b,
            0x9c90a44fad53d2d1,
            0xd1542d9374a67fef,
            0x23f683062e9e65eb,
        ),
        u: GFp5::from_u64_reduce(
            0x98c6fbb81dc121c1,
            0x4c2c310848e48d1b,
            0xcf8082bcb5e7d69a,
            0x9b495103371a673c,
            0x4a5e8a2e23c4d340,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0x6ac4419c7277d1ca,
            0x2c5c1f5e44b298d7,
            0x18c662c232d514dd,
            0x44d950568161e181,
            0xe714ce4b73a7b072,
        ),
        u: GFp5::from_u64_reduce(
            0xa81d41aaaf4fa6cf,
            0x6e1de35fdad17243,
            0xc98288b163f43776,
            0x130ab99648d7bd44,
            0x9c417a9bafab5466,
        ),
    },
];

pub(crate) const G240: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0xa8a0ee7803a9262a,
            0x3a9e64856ddf4568,
            0xa8d15981c6b5e366,
            0x8c50dfc96818c3f6,
            0x67747da91ea27afa,
        ),
        u: GFp5::from_u64_reduce(
            0x721e3407ebd5f510,
            0xcd45a5fb06b5d837,
            0x5adf593fef90259d,
            0xc3b0ffb9aa1c972a,
            0x86ef37ac9f5cf331,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0x200e8b5c9c37e3af,
            0x921c4cd1d43b733e,
            0x285f3cfa7b98bdeb,
            0xc43d0057a09411a4,
            0xcabd6e7dc2d3243a,
        ),
        u: GFp5::from_u64_reduce(
            0xb8c8962cb51c8455,
            0x27e98000626d107c,
            0x8d9e90eea287f110,
            0x2315d937d3b14704,
            0xd855ed171240a04f,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0x8ebdf4139f2ac3bc,
            0x5ebd2fdbae6ee6dc,
            0x329010a7f5f44d0b,
            0x30eb8fffb8a0547e,
            0x8094d0cd6d63e13f,
        ),
        u: GFp5::from_u64_reduce(
            0xffc1c1d1edb1fd4d,
            0xe2b3a119fc8e2d33,
            0x140d049877e3268b,
            0x0763801996111cc8,
            0xe55eb94944d8fd3f,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0x4f2a667724e34e0c,
            0x66c0d5f79375414f,
            0x91398d556c18de95,
            0x56b37c05a0068fda,
            0x46fd0da0d321a8d0,
        ),
        u: GFp5::from_u64_reduce(
            0xf3f7f65aadc697ee,
            0x2498fbe550d9998d,
            0x42d957d8d25dcc73,
            0x0371646cb0db7f11,
            0x3ee41b5b478efe53,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0x3dffe1fb511b6c11,
            0x07bfd5aee108720c,
            0x4140011508479da9,
            0xe725984d11458168,
            0xcfd5c8aeba6beb4f,
        ),
        u: GFp5::from_u64_reduce(
            0x3f0b1b59fcfeb6f7,
            0xf78eecbe0e1a6029,
            0x358349b2f8b945c6,
            0x33490e5bbc1fd56a,
            0x932ee56afe959d14,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0x853d24b74b77be2d,
            0x28d86d666ff156dc,
            0x6824e07bdfd14641,
            0x3236f2172775afa1,
            0x6efb083efc900f5b,
        ),
        u: GFp5::from_u64_reduce(
            0x11c1ca68d2b4998e,
            0x4206817db4e66eb6,
            0xac5ea5717a533864,
            0xecb4c2dee8ba26a1,
            0xdeeb73f656d8ad27,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0x0089d625d4a275fe,
            0x4aee1c1c159e64a8,
            0xcf02452bb6abe083,
            0x097802619a3cd9e8,
            0xfc53d6aede0e9fe9,
        ),
        u: GFp5::from_u64_reduce(
            0x435279229bd3625c,
            0x1889895fe07c89e2,
            0xe056ddc0f402ce97,
            0xe804e68342f959d9,
            0x2f028095d09c7904,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0x1cd80828e1157548,
            0x7ab3312b81cbd770,
            0xa191b99e0f818f66,
            0x36ffee5a4112c1f2,
            0xad3f8ac8ad921e49,
        ),
        u: GFp5::from_u64_reduce(
            0xbf4f161f2614dcfb,
            0x7587b98e8a95aaf7,
            0x2c0ec2b7f5f7cbb8,
            0x95e505d4a14af60a,
            0xb45d26196646c9af,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0x8a9ce262c5329443,
            0x07a3b8c865423f4f,
            0xe018203aa3102625,
            0x9f596f7b6817c8c1,
            0xfcb769579909678b,
        ),
        u: GFp5::from_u64_reduce(
            0xefd12fc70b32aab2,
            0x47630ed573839dae,
            0x8311d5c3758990f4,
            0x20a8765c516f9bcf,
            0x679a6d91ff5dd6d2,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x5af23895a8573e74,
            0xf6ac9da9076a8710,
            0x7162587ae722ef71,
            0xe4b3bcce6873a42d,
            0x7da1f5cd972d59c1,
        ),
        u: GFp5::from_u64_reduce(
            0x461b13504d813650,
            0x70ff153c0b3881be,
            0x5be064c9652c1cf9,
            0xd64c780542d5c6d8,
            0xf783c2ad3e4e50b8,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0xb2ac7989c02502e9,
            0x46f0a5085fd69389,
            0x83ad6be496c248d3,
            0x1fe71326a8f0a166,
            0xd75068c5d239ed41,
        ),
        u: GFp5::from_u64_reduce(
            0x89de70d73d84658d,
            0x437c5714fe4f8b2c,
            0x63cd50470844c646,
            0xaeb39b4dc0637ed3,
            0xe96ce8d06024a136,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0x4c6b70fef9176c74,
            0x6dd1a052ceb84b64,
            0xec6b6236bc4cdb96,
            0xa995d28da35ccbba,
            0x413da1c9356b35bb,
        ),
        u: GFp5::from_u64_reduce(
            0xd8e20d8054e422dd,
            0x8a5c4188e9409b51,
            0x3798827d3aae1108,
            0x9e75ffac84dabfea,
            0x8455308253067827,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0x092be4d5b779ce6e,
            0x205d65d92c7bbe5a,
            0x4410382623dcc479,
            0xf426801189b81eeb,
            0x18a49aedbad87946,
        ),
        u: GFp5::from_u64_reduce(
            0x72e31c8a73e2a5f2,
            0x038d4fcb2d0d45f9,
            0xface7bbc088c9465,
            0x4d8a29c235ce48df,
            0x6dde986c6f3de573,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0xce8281832197f5e7,
            0x02df944fe891e27e,
            0x7c32b2ac7ca4df96,
            0xddde4642c673e511,
            0x910884a15c6e9e90,
        ),
        u: GFp5::from_u64_reduce(
            0x927b31caa1595d30,
            0x9ab94754b9b1c1c8,
            0xb0ffe7ef45ad9608,
            0x5617f7967dc07dd7,
            0x748b52fc2f538f06,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0x85987ce43845212c,
            0x0e13745d09a067d9,
            0xae4d3c09c5d3b59c,
            0x17dcce2f3bc41e08,
            0xa8dd0b19fe8df324,
        ),
        u: GFp5::from_u64_reduce(
            0x8b52dbac4316df3c,
            0xe6dd1b0b096ba49b,
            0x45b50205a85d4930,
            0xbca014ccf49a96cf,
            0x43ef77c96a70c64d,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0xd253f638008f64d9,
            0x300911f4cf750079,
            0xeba4c0ccf84421f1,
            0xd9a8ec0a382cc42a,
            0xb2b4d66cac8fda35,
        ),
        u: GFp5::from_u64_reduce(
            0x8c725dfae21259fb,
            0xa93424c7a5fc6938,
            0x97ce72fe5a59c0ef,
            0xa8ee2e81bca93cbc,
            0x3b54ad70a6670624,
        ),
    },
];

pub(crate) const G280: [PointAffine; 16] = [
    PointAffine {
        /* 1 */
        x: GFp5::from_u64_reduce(
            0xe101efe0dd3d126e,
            0xee415579e7763701,
            0x481dbdd5a30063d0,
            0x9a4a5a2ce9dc78d0,
            0x70dff28028661446,
        ),
        u: GFp5::from_u64_reduce(
            0x9de418bd4b624fa5,
            0x3e080a3e987b0f4d,
            0x7d171e8a81daf782,
            0x13b661fef2d14550,
            0xe193cbfc0ec5427a,
        ),
    },
    PointAffine {
        /* 2 */
        x: GFp5::from_u64_reduce(
            0x5df5ec1abf7f91f1,
            0xed85bea6eacb5e1c,
            0x571dea21506d257f,
            0x81fecbefee649a35,
            0x60c9a0d1fa6944fb,
        ),
        u: GFp5::from_u64_reduce(
            0x17b12a9cd0da93bd,
            0xe34f65a1c5fe95e5,
            0x85402906eab91693,
            0xff1bf5f49ae493a4,
            0x8839e8685fae3e48,
        ),
    },
    PointAffine {
        /* 3 */
        x: GFp5::from_u64_reduce(
            0x80fbeef7cd2e13c8,
            0xedbc56cce4b4bdb9,
            0xf6d0c9c57a7d8082,
            0x6daf1cfc656e1455,
            0xba7e4182b917f1fd,
        ),
        u: GFp5::from_u64_reduce(
            0xce0efda5f6b68e02,
            0x35cca934993eddea,
            0xf41b71bdb24254f1,
            0xb7f6c4594149ee3d,
            0xe9a7895f548783e2,
        ),
    },
    PointAffine {
        /* 4 */
        x: GFp5::from_u64_reduce(
            0x59fe2ab81abb02ae,
            0xcbadfccb2f04b57a,
            0x0d1969f23952938d,
            0x831c8c1258cae189,
            0xeb843136ea9a94fc,
        ),
        u: GFp5::from_u64_reduce(
            0x608228855343e93e,
            0x78091b902f3a0e56,
            0x27e3ec97b5f1d957,
            0x5e3fcaa84d86532d,
            0x40fd2108182d5785,
        ),
    },
    PointAffine {
        /* 5 */
        x: GFp5::from_u64_reduce(
            0xf7beb6dbf433a526,
            0x0b2a53c27e29826c,
            0x88809f3b7adfe4d6,
            0x269d7073c55388ba,
            0x99104832d8d4c84c,
        ),
        u: GFp5::from_u64_reduce(
            0xf10d0d94cd8a08e4,
            0x9fe8f86bf58a0740,
            0x922b67e3f366c40b,
            0xd15574f1fd92b0cf,
            0xab3245eea77d39a7,
        ),
    },
    PointAffine {
        /* 6 */
        x: GFp5::from_u64_reduce(
            0xf8cc69057f7c5225,
            0x0db771295ea9b3f1,
            0xedc9814f24289219,
            0x33fb7a518409da5a,
            0xa7a4b6dedf49f9b2,
        ),
        u: GFp5::from_u64_reduce(
            0xe82170da6be518e0,
            0xe7b7459b42536ceb,
            0x188951de0336cd0e,
            0x47ec99ca8dfd40b5,
            0xb319a211d2ef9288,
        ),
    },
    PointAffine {
        /* 7 */
        x: GFp5::from_u64_reduce(
            0x48b43db63c7204a7,
            0x69ec0cfebe4f89d8,
            0xb700d394422584b0,
            0x4a91affadc8c6c71,
            0x42345336177b3c4c,
        ),
        u: GFp5::from_u64_reduce(
            0x0c92df3450e3302a,
            0x230917e124b9227e,
            0x1846f380dff4f6ec,
            0x7498858a1257454f,
            0xbfa3a9af58cb8e48,
        ),
    },
    PointAffine {
        /* 8 */
        x: GFp5::from_u64_reduce(
            0x300fe3b1cbd6a543,
            0x82b53fa07658d890,
            0xe704a58ce42e61e5,
            0x6fb145c2e7eb6299,
            0x378def33925deb86,
        ),
        u: GFp5::from_u64_reduce(
            0x07dad4739750d586,
            0x4e42edc099cee5a1,
            0x30a64ba70df477fc,
            0x0b7e53d8154398e7,
            0x27a84d1c4843d524,
        ),
    },
    PointAffine {
        /* 9 */
        x: GFp5::from_u64_reduce(
            0x92d2d5b7ef4eab2a,
            0x13ca27355fd36907,
            0x3d9538f8c489f69f,
            0x7fc99fc81c60ec16,
            0x70e05ce274b2dda7,
        ),
        u: GFp5::from_u64_reduce(
            0x4dd5f5e8aa5f8b6c,
            0xcb929b26407014dc,
            0x30f1214c5e00b284,
            0xe0bb4238490f1785,
            0xcd979b08c903acce,
        ),
    },
    PointAffine {
        /* 10 */
        x: GFp5::from_u64_reduce(
            0x5a7572dbfd2428dd,
            0x8e7b9fafcdfbed39,
            0x62a60250ab74ddf1,
            0xcb2e17da9e0be40f,
            0x5bf6b50f358ad87f,
        ),
        u: GFp5::from_u64_reduce(
            0xc93002fecfba924f,
            0x20bddd4fa0c3967d,
            0x7aed8f011da76fe7,
            0xedcac7d07bfcd27d,
            0x2926364889ce6286,
        ),
    },
    PointAffine {
        /* 11 */
        x: GFp5::from_u64_reduce(
            0x2ce1d8a8f8c936c9,
            0x2cc208d366e2ac94,
            0x6257c9ed583d473d,
            0xb2b56863b06a3eda,
            0xa07329d48db98857,
        ),
        u: GFp5::from_u64_reduce(
            0x27258dd37498fc8e,
            0xe1e1dcda4ff7613d,
            0x755f5bf95a6ab233,
            0x032742ac5790144f,
            0x815e83a0eaaf5b08,
        ),
    },
    PointAffine {
        /* 12 */
        x: GFp5::from_u64_reduce(
            0x805fa56682dc7521,
            0x1884fa5cffb9706b,
            0xbad790c71f9faa62,
            0xb96900bba4d86e22,
            0x6f42c94a933a1d71,
        ),
        u: GFp5::from_u64_reduce(
            0x1f4bb93538bc8ad3,
            0x84225ec5aefe8090,
            0x25c275174590a594,
            0x9feea6c1e2a5f099,
            0x19b8897561179347,
        ),
    },
    PointAffine {
        /* 13 */
        x: GFp5::from_u64_reduce(
            0x2955e592eb1efe5a,
            0x7a282b0798a33c54,
            0x74ba891f8a832b8b,
            0x7c6d6a557f1625fd,
            0x019718b0db5a0fb0,
        ),
        u: GFp5::from_u64_reduce(
            0x8e71b3c48df30d11,
            0x82b0b16111166a18,
            0x5da9b5bc441b0f5c,
            0x52c893875d4fc42a,
            0x4a94adfbbcab9093,
        ),
    },
    PointAffine {
        /* 14 */
        x: GFp5::from_u64_reduce(
            0x9c61b93a717ac45d,
            0x2cbca52f2d36f2b3,
            0x4289e63d03b28d39,
            0x82919f9e399e7d80,
            0x8633a31b3179f23b,
        ),
        u: GFp5::from_u64_reduce(
            0x071f2e41d3cc3e52,
            0x5cef76b14b6f9011,
            0xd12158d2928c481b,
            0x76020b56eb95afbe,
            0x81f94088fbd89c53,
        ),
    },
    PointAffine {
        /* 15 */
        x: GFp5::from_u64_reduce(
            0x7a657d2637ebb4e5,
            0x5d2ed7179b27bf7a,
            0xa7c592d6837d8e67,
            0xedaeb459581e2034,
            0xd89552c3f92aca28,
        ),
        u: GFp5::from_u64_reduce(
            0xffa6c86c78a12912,
            0xce9bd2556518e6ab,
            0xe8e07519d7635b1a,
            0x962eda250276acf0,
            0x5c941dc8238f8eed,
        ),
    },
    PointAffine {
        /* 16 */
        x: GFp5::from_u64_reduce(
            0x33e179a5f02ea96f,
            0x35486a003e0c192e,
            0x8a17fdb3a32f31a9,
            0xbcb9c322fe0b8da8,
            0x7162143807aa558c,
        ),
        u: GFp5::from_u64_reduce(
            0xf1848305499b4272,
            0xaa60a5f08c4015f2,
            0x01dfeb78a828f5bc,
            0x5e8f88cd8a52f258,
            0xdc499e276a245215,
        ),
    },
];
