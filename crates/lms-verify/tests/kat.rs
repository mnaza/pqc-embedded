//! Known-answer tests against the RFC 8554 published vectors.
//!
//! # Provenance
//!
//! Every byte below is transcribed from **RFC 8554, Appendix F**, fetched from
//! `https://www.rfc-editor.org/rfc/rfc8554.txt`. Nothing here was produced by this
//! crate. That is the point: the tests in `src/lib.rs` are round trips between this
//! crate's test signer and this crate's verifier, so they prove the two agree with
//! each other and nothing more. A wrong domain separator, or a wrong endianness in
//! `u32str`, would land in both halves identically and pass in silence. These
//! vectors are the independent check.
//!
//! # Getting bare LMS vectors out of HSS test cases
//!
//! Appendix F publishes **HSS** (hierarchical) test cases rather than bare LMS
//! ones, so they cannot be dropped straight in. They come apart cleanly, and the
//! structure is convenient. An HSS signature with `Nspk = 1` is
//!
//! ```text
//!   u32str(Nspk) || sig[0] || pub[1] || sig[1]
//! ```
//!
//! where `sig[0]` is the root tree's LMS signature over the **serialised level-1
//! public key**, and `sig[1]` is the level-1 tree's LMS signature over the actual
//! message. Each is an ordinary LMS signature and verifies on its own, so every HSS
//! test case yields two independent bare-LMS checks — one where the signed message
//! happens to be a 56-byte public key, one where it is ordinary text.
//!
//! Between them the two test cases exercise both parameter combinations this crate
//! implements, which the round-trip tests could only do at h=5:
//!
//! | vector | LMS | LM-OTS | signature |
//! |---|---|---|---|
//! | TC1 sig\[0\], sig\[1\] | H5 | W8 | 1292 B |
//! | TC2 sig\[0\] | H10 | W4 | 2508 B |
//! | TC2 sig\[1\] | H5 | W8 | 1292 B |
//!
//! # Negative vectors
//!
//! The tampered cases below are derived from the genuine vectors by mutating one
//! byte, never invented. A verifier that accepts a valid signature is only half
//! tested; the half that matters for boot is that it rejects everything else, and
//! rejects it with the reason it claims.

/// Decode transcribed hex. Panics on anything that is not hex, which in a test is
/// the right response to a typo in a vector.
fn hex(parts: &[&str]) -> Vec<u8> {
    let joined: String = parts.concat();
    assert_eq!(joined.len() % 2, 0, "odd number of hex digits");
    (0..joined.len() / 2)
        .map(|i| u8::from_str_radix(&joined[2 * i..2 * i + 2], 16).expect("valid hex"))
        .collect()
}

// --------------------------------------------------------------------------
// RFC 8554 Appendix F, Test Case 1 - LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8
// --------------------------------------------------------------------------

/// Root LMS public key, with the HSS `levels` field stripped.
const TC1_PK_ROOT: &[&str] = &[
    "000000050000000461a5d57d37f5e46bfb7520806b07a1b850650e3b31fe4a77",
    "3ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878",
];

/// The signed message: the text of the Tenth Amendment.
const TC1_MSG: &[&str] = &[
    "54686520706f77657273206e6f742064656c65676174656420746f2074686520",
    "556e69746564205374617465732062792074686520436f6e737469747574696f",
    "6e2c206e6f722070726f6869626974656420627920697420746f207468652053",
    "74617465732c2061726520726573657276656420746f20746865205374617465",
    "7320726573706563746976656c792c206f7220746f207468652070656f706c65",
    "2e0a",
];

/// Root tree signature over the serialised level-1 public key.
const TC1_SIG0: &[&str] = &[
    "0000000500000004d32b56671d7eb98833c49b433c272586bc4a1c8a8970528f",
    "fa04b966f9426eb9965a25bfd37f196b9073f3d4a232feb69128ec45146f8629",
    "2f9dff9610a7bf95a64c7f60f6261a62043f86c70324b7707f5b4a8a6e19c114",
    "c7be866d488778a0e05fd5c6509a6e61d559cf1a77a970de927d60c70d3de31a",
    "7fa0100994e162a2582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9",
    "b9c96b83a4943d1681d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2",
    "518eb20de2f66e3b14784269d7d876f5d35d3fbfc7039a462c716bb9f6891a7f",
    "41ad133e9e1f6d9560b960e7777c52f060492f2d7c660e1471e07e7265556203",
    "5abc9a701b473ecbc3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f428bab6f",
    "3a30f55dd9625563f0a75ee390e385e3ae0b906961ecf41ae073a0590c2eb620",
    "4f44831c26dd768c35b167b28ce8dc988a3748255230cef99ebf14e730632f27",
    "414489808afab1d1e783ed04516de012498682212b07810579b250365941bcc9",
    "8142da13609e9768aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb",
    "8dec2fc0e7f932701099762b37f43c4a3c20010a3d72e2f606be108d310e639f",
    "09ce7286800d9ef8a1a40281cc5a7ea98d2adc7c7400c2fe5a101552df4e3ccc",
    "fd0cbf2ddf5dc6779cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73c",
    "cdcf3c79e6580c154f8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb07",
    "7f66ded5bec73b27c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c196",
    "74f190c9fbc506d826857713afd2ca6bb85cd8c107347552f30575a5417816ab",
    "4db3f603f2df56fbc413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403",
    "466b1afe78b94f7ecf7cc62fb92be14f18c2192384ebceaf8801afdf947f698c",
    "e9c6ceb696ed70e9e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8",
    "d8cb2a661ce3b57ada67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f17",
    "1cf469c76b884cf3115cce6f792cc84e36da58960c5f1d760f32c12faef477e9",
    "4c92eb75625b6a371efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbd",
    "c3ce9704882a2072c75e13527b7a581a556168783dc1e97545e31865ddc46b3c",
    "957835da252bb7328d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0a",
    "f1e0bc017351aae2ab8f5c612ead0b729a1d059d02bfe18efa971b7300e88236",
    "0a93b025ff97e9e0eec0f3f3f13039a17f88b0cf808f488431606cb13f9241f4",
    "0f44e537d302c64a4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510f150c85f",
    "b525bf25703df7209b6066f09c37280d59128d2f0f637c7d7d7fad4ed1c1ea04",
    "e628d221e3d8db77b7c878c9411cafc5071a34a00f4cf07738912753dfce48f0",
    "7576f0d4f94f42c6d76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1",
    "044c96aefee67676401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f0862",
    "78dd8ad0686078dfb0f3f79cd893d314168648499898fbc0ced5f95b74e8ff14",
    "d735cdea968bee7400000005d8b8112f9200a5e50c4a262165bd342cd800b849",
    "6810bc716277435ac376728d129ac6eda839a6f357b5a04387c5ce97382a78f2",
    "a4372917eefcbf93f63bb59112f5dbe400bd49e4501e859f885bf0736e90a509",
    "b30a26bfac8c17b5991c157eb5971115aa39efd8d564a6b90282c3168af2d30e",
    "f89d51bf14654510a12b8a144cca1848cf7da59cc2b3d9d0692dd2a20ba38634",
    "80e25b1b85ee860c62bf5136",
];

/// Level-1 LMS public key. Also the message that `TC1_SIG0` signs.
const TC1_PK1: &[&str] = &[
    "0000000500000004d2f14ff6346af964569f7d6cb880a1b66c5004917da6eafe",
    "4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab",
];

/// Level-1 tree signature over `TC1_MSG`.
const TC1_SIG1: &[&str] = &[
    "0000000a000000040703c491e7558b35011ece3592eaa5da4d918786771233e8",
    "353bc4f62323185c95cae05b899e35dffd717054706209988ebfdf6e37960bb5",
    "c38d7657e8bffeef9bc042da4b4525650485c66d0ce19b317587c6ba4bffcc42",
    "8e25d08931e72dfb6a120c5612344258b85efdb7db1db9e1865a73caf96557eb",
    "39ed3e3f426933ac9eeddb03a1d2374af7bf77185577456237f9de2d60113c23",
    "f846df26fa942008a698994c0827d90e86d43e0df7f4bfcdb09b86a373b98288",
    "b7094ad81a0185ac100e4f2c5fc38c003c1ab6fea479eb2f5ebe48f584d7159b",
    "8ada03586e65ad9c969f6aecbfe44cf356888a7b15a3ff074f771760b26f9c04",
    "884ee1faa329fbf4e61af23aee7fa5d4d9a5dfcf43c4c26ce8aea2ce8a2990d7",
    "ba7b57108b47dabfbeadb2b25b3cacc1ac0cef346cbb90fb044beee4fac2603a",
    "442bdf7e507243b7319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2",
    "315f3d36ef2eaa3cf30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd",
    "61ddfee81aca9ce60081262a00000480dcbc9a3da6fbef5c1c0a55e48a0e729f",
    "9184fcb1407c31529db268f6fe50032a363c9801306837fafabdf957fd97eafc",
    "80dbd165e435d0e2dfd836a28b354023924b6fb7e48bc0b3ed95eea64c2d402f",
    "4d734c8dc26f3ac591825daef01eae3c38e3328d00a77dc657034f287ccb0f0e",
    "1c9a7cbdc828f627205e4737b84b58376551d44c12c3c215c812a0970789c83d",
    "e51d6ad787271963327f0a5fbb6b5907dec02c9a90934af5a1c63b72c8265360",
    "5d1dcce51596b3c2b45696689f2eb382007497557692caac4d57b5de9f5569bc",
    "2ad0137fd47fb47e664fcb6db4971f5b3e07aceda9ac130e9f38182de994cff1",
    "92ec0e82fd6d4cb7f3fe00812589b7a7ce515440456433016b84a59bec6619a1",
    "c6c0b37dd1450ed4f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2cc06fa8c8",
    "2bed4d944e71339ece780fd025bd41ec34ebff9d4270a3224e019fcb444474d4",
    "82fd2dbe75efb20389cc10cd600abb54c47ede93e08c114edb04117d714dc1d5",
    "25e11bed8756192f929d15462b939ff3f52f2252da2ed64d8fae88818b1efa2c",
    "7b08c8794fb1b214aa233db3162833141ea4383f1a6f120be1db82ce3630b342",
    "9114463157a64e91234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6a",
    "ad2831db61274993715a0182c7dc8089e32c8531deed4f7431c07c02195eba2e",
    "f91efb5613c37af7ae0c066babc69369700e1dd26eddc0d216c781d56e4ce47e",
    "3303fa73007ff7b949ef23be2aa4dbf25206fe45c20dd888395b2526391a7249",
    "96a44156beac808212858792bf8e74cba49dee5e8812e019da87454bff9e847e",
    "d83db07af313743082f880a278f682c2bd0ad6887cb59f652e155987d61bbf6a",
    "88d36ee93b6072e6656d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3",
    "b3539eb77b248a661091d05eb6e2f297774fe6053598457cc61908318de4b826",
    "f0fc86d4bb117d33e865aa805009cc2918d9c2f840c4da43a703ad9f5b580616",
    "3d7161696b5a0adc00000005d5c0d1bebb06048ed6fe2ef2c6cef305b3ed6339",
    "41ebc8b3bec9738754cddd60e1920ada52f43d055b5031cee6192520d6a51155",
    "14851ce7fd448d4a39fae2ab2335b525f484e9b40d6a4a969394843bdcf6d14c",
    "48e8015e08ab92662c05c6e9f90b65a7a6201689999f32bfd368e5e3ec9cb70a",
    "c7b8399003f175c40885081a09ab3034911fe125631051df0408b3946b0bde79",
    "0911e8978ba07dd56c73e7ee",
];

// --------------------------------------------------------------------------
// RFC 8554 Appendix F, Test Case 2 - root H10/W4, level-1 H5/W8
// --------------------------------------------------------------------------

/// Root LMS public key: LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4.
const TC2_PK_ROOT: &[&str] = &[
    "0000000600000003d08fabd4a2091ff0a8cb4ed834e7453432a58885cd9ba043",
    "1235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e",
];

/// The signed message: the text of the Ninth Amendment.
const TC2_MSG: &[&str] = &[
    "54686520656e756d65726174696f6e20696e2074686520436f6e737469747574",
    "696f6e2c206f66206365727461696e207269676874732c207368616c6c206e6f",
    "7420626520636f6e73747275656420746f2064656e79206f7220646973706172",
    "616765206f74686572732072657461696e6564206279207468652070656f706c",
    "652e0a",
];

/// Root tree signature. The h=10, w=4 case, 2508 bytes.
const TC2_SIG0: &[&str] = &[
    "00000003000000033d46bee8660f8f215d3f96408a7a64cf1c4da02b63a55f62",
    "c666ef5707a914ce0674e8cb7a55f0c48d484f31f3aa4af9719a74f22cf823b9",
    "4431d01c926e2a76bb71226d279700ec81c9e95fb11a0d10d065279a5796e265",
    "ae17737c44eb8c594508e126a9a7870bf4360820bdeb9a01d9693779e416828e",
    "75bddd7d8c70d50a0ac8ba39810909d445f44cb5bb58de737e60cb4345302786",
    "ef2c6b14af212ca19edeaa3bfcfe8baa6621ce88480df2371dd37add732c9de4",
    "ea2ce0dffa53c92649a18d39a50788f4652987f226a1d48168205df6ae7c58e0",
    "49a25d4907edc1aa90da8aa5e5f7671773e941d8055360215c6b60dd35463cf2",
    "240a9c06d694e9cb54e7b1e1bf494d0d1a28c0d31acc75161f4f485dfd3cb957",
    "8e836ec2dc722f37ed30872e07f2b8bd0374eb57d22c614e09150f6c0d8774a3",
    "9a6e168211035dc52988ab46eaca9ec597fb18b4936e66ef2f0df26e8d1e34da",
    "28cbb3af752313720c7b345434f72d65314328bbb030d0f0f6d5e47b28ea9100",
    "8fb11b05017705a8be3b2adb83c60a54f9d1d1b2f476f9e393eb5695203d2ba6",
    "ad815e6a111ea293dcc21033f9453d49c8e5a6387f588b1ea4f706217c151e05",
    "f55a6eb7997be09d56a326a32f9cba1fbe1c07bb49fa04cecf9df1a1b815483c",
    "75d7a27cc88ad1b1238e5ea986b53e087045723ce16187eda22e33b2c70709e5",
    "3251025abde8939645fc8c0693e97763928f00b2e3c75af3942d8ddaee81b59a",
    "6f1f67efda0ef81d11873b59137f67800b35e81b01563d187c4a1575a1acb92d",
    "087b517a8833383f05d357ef4678de0c57ff9f1b2da61dfde5d88318bcdde4d9",
    "061cc75c2de3cd4740dd7739ca3ef66f1930026f47d9ebaa713b07176f76f953",
    "e1c2e7f8f271a6ca375dbfb83d719b1635a7d8a13891957944b1c29bb101913e",
    "166e11bd5f34186fa6c0a555c9026b256a6860f4866bd6d0b5bf90627086c614",
    "9133f8282ce6c9b3622442443d5eca959d6c14ca8389d12c4068b503e4e3c39b",
    "635bea245d9d05a2558f249c9661c0427d2e489ca5b5dde220a90333f4862aec",
    "793223c781997da98266c12c50ea28b2c438e7a379eb106eca0c7fd6006e9bf6",
    "12f3ea0a454ba3bdb76e8027992e60de01e9094fddeb3349883914fb17a9621a",
    "b929d970d101e45f8278c14b032bcab02bd15692d21b6c5c204abbf077d46555",
    "3bd6eda645e6c3065d33b10d518a61e15ed0f092c32226281a29c8a0f50cde0a",
    "8c66236e29c2f310a375cebda1dc6bb9a1a01dae6c7aba8ebedc6371a7d52aac",
    "b955f83bd6e4f84d2949dcc198fb77c7e5cdf6040b0f84faf82808bf985577f0",
    "a2acf2ec7ed7c0b0ae8a270e951743ff23e0b2dd12e9c3c828fb5598a22461af",
    "94d568f29240ba2820c4591f71c088f96e095dd98beae456579ebbba36f6d9ca",
    "2613d1c26eee4d8c73217ac5962b5f3147b492e8831597fd89b64aa7fde82e19",
    "74d2f6779504dc21435eb3109350756b9fdabe1c6f368081bd40b27ebcb9819a",
    "75d7df8bb07bb05db1bab705a4b7e37125186339464ad8faaa4f052cc1272919",
    "fde3e025bb64aa8e0eb1fcbfcc25acb5f718ce4f7c2182fb393a1814b0e94249",
    "0e52d3bca817b2b26e90d4c9b0cc38608a6cef5eb153af0858acc867c9922aed",
    "43bb67d7b33acc519313d28d41a5c6fe6cf3595dd5ee63f0a4c4065a083590b2",
    "75788bee7ad875a7f88dd73720708c6c6c0ecf1f43bbaadae6f208557fdc07bd",
    "4ed91f88ce4c0de842761c70c186bfdafafc444834bd3418be4253a71eaf41d7",
    "18753ad07754ca3effd5960b0336981795721426803599ed5b2b7516920efcbe",
    "32ada4bcf6c73bd29e3fa152d9adeca36020fdeeee1b739521d3ea8c0da49700",
    "3df1513897b0f54794a873670b8d93bcca2ae47e64424b7423e1f078d9554bb5",
    "232cc6de8aae9b83fa5b9510beb39ccf4b4e1d9c0f19d5e17f58e5b8705d9a68",
    "37a7d9bf99cd13387af256a8491671f1f2f22af253bcff54b673199bdb7d05d8",
    "1064ef05f80f0153d0be7919684b23da8d42ff3effdb7ca0985033f389181f47",
    "659138003d712b5ec0a614d31cc7487f52de8664916af79c98456b2c94a80380",
    "83db55391e3475862250274a1de2584fec975fb09536792cfbfcf6192856cc76",
    "eb5b13dc4709e2f7301ddff26ec1b23de2d188c999166c74e1e14bbc15f457cf",
    "4e471ae13dcbdd9c50f4d646fc6278e8fe7eb6cb5c94100fa870187380b777ed",
    "19d7868fd8ca7ceb7fa7d5cc861c5bdac98e7495eb0a2ceec1924ae979f44c53",
    "90ebedddc65d6ec11287d978b8df064219bc5679f7d7b264a76ff272b2ac9f2f",
    "7cfc9fdcfb6a51428240027afd9d52a79b647c90c2709e060ed70f87299dd798",
    "d68f4fadd3da6c51d839f851f98f67840b964ebe73f8cec41572538ec6bc1310",
    "34ca2894eb736b3bda93d9f5f6fa6f6c0f03ce43362b8414940355fb54d3dfdd",
    "03633ae108f3de3ebc85a3ff51efeea3bc2cf27e1658f1789ee612c83d0f5fd5",
    "6f7cd071930e2946beeecaa04dccea9f97786001475e0294bc2852f62eb5d39b",
    "b9fbeef75916efe44a662ecae37ede27e9d6eadfdeb8f8b2b2dbccbf96fa6dba",
    "f7321fb0e701f4d429c2f4dcd153a2742574126e5eaccc77686acf6e3ee48f42",
    "3766e0fc466810a905ff5453ec99897b56bc55dd49b991142f65043f2d744eeb",
    "935ba7f4ef23cf80cc5a8a335d3619d781e7454826df720eec82e06034c44699",
    "b5f0c44a8787752e057fa3419b5bb0e25d30981e41cb1361322dba8f69931cf4",
    "2fad3f3bce6ded5b8bfc3d20a2148861b2afc14562ddd27f12897abf0685288d",
    "cc5c4982f826026846a24bf77e383c7aacab1ab692b29ed8c018a65f3dc2b87f",
    "f619a633c41b4fadb1c78725c1f8f922f6009787b1964247df0136b1bc614ab5",
    "75c59a16d089917bd4a8b6f04d95c581279a139be09fcf6e98a470a0bceca191",
    "fce476f9370021cbc05518a7efd35d89d8577c990a5e19961ba16203c959c918",
    "29ba7497cffcbb4b294546454fa5388a23a22e805a5ca35f956598848bda6786",
    "15fec28afd5da61a00000006b326493313053ced3876db9d237148181b7173bc",
    "7d042cefb4dbe94d2e58cd21a769db4657a103279ba8ef3a629ca84ee836172a",
    "9c50e51f45581741cf8083150b491cb4ecbbabec128e7c81a46e62a67b57640a",
    "0a78be1cbf7dd9d419a10cd8686d16621a80816bfdb5bdc56211d72ca70b81f1",
    "117d129529a7570cf79cf52a7028a48538ecdd3b38d3d5d62d26246595c4fb73",
    "a525a5ed2c30524ebb1d8cc82e0c19bc4977c6898ff95fd3d310b0bae71696ce",
    "f93c6a552456bf96e9d075e383bb7543c675842bafbfc7cdb88483b3276c29d4",
    "f0a341c2d406e40d4653b7e4d045851acf6a0a0ea9c710b805cced4635ee8c10",
    "7362f0fc8d80c14d0ac49c516703d26d14752f34c1c0d2c4247581c18c2cf4de",
    "48e9ce949be7c888e9caebe4a415e291fd107d21dc1f084b1158208249f28f4f",
    "7c7e931ba7b3bd0d824a4570",
];

/// Level-1 LMS public key: LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8.
const TC2_PK1: &[&str] = &[
    "0000000500000004215f83b7ccb9acbcd08db97b0d04dc2ba1cd035833e0e900",
    "59603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b7",
];

/// Level-1 tree signature over `TC2_MSG`.
const TC2_SIG1: &[&str] = &[
    "00000004000000040eb1ed54a2460d512388cad533138d240534e97b1e82d33b",
    "d927d201dfc24ebb11b3649023696f85150b189e50c00e98850ac343a77b3638",
    "319c347d7310269d3b7714fa406b8c35b021d54d4fdada7b9ce5d4ba5b06719e",
    "72aaf58c5aae7aca057aa0e2e74e7dcfd17a0823429db62965b7d563c57b4cec",
    "942cc865e29c1dad83cac8b4d61aacc457f336e6a10b66323f5887bf3523dfca",
    "dee158503bfaa89dc6bf59daa82afd2b5ebb2a9ca6572a6067cee7c327e9039b",
    "3b6ea6a1edc7fdc3df927aade10c1c9f2d5ff446450d2a3998d0f9f6202b5e07",
    "c3f97d2458c69d3c8190643978d7a7f4d64e97e3f1c4a08a7c5bc03fd55682c0",
    "17e2907eab07e5bb2f190143475a6043d5e6d5263471f4eecf6e2575fbc6ff37",
    "edfa249d6cda1a09f797fd5a3cd53a066700f45863f04b6c8a58cfd341241e00",
    "2d0d2c0217472bf18b636ae547c1771368d9f317835c9b0ef430b3df4034f6af",
    "00d0da44f4af7800bc7a5cf8a5abdb12dc718b559b74cab9090e33cc58a95530",
    "0981c420c4da8ffd67df540890a062fe40dba8b2c1c548ced22473219c534911",
    "d48ccaabfb71bc71862f4a24ebd376d288fd4e6fb06ed8705787c5fedc813cd2",
    "697e5b1aac1ced45767b14ce88409eaebb601a93559aae893e143d1c395bc326",
    "da821d79a9ed41dcfbe549147f71c092f4f3ac522b5cc57290706650487bae9b",
    "b5671ecc9ccc2ce51ead87ac01985268521222fb9057df7ed41810b5ef0d4f7c",
    "c67368c90f573b1ac2ce956c365ed38e893ce7b2fae15d3685a3df2fa3d4cc09",
    "8fa57dd60d2c9754a8ade980ad0f93f6787075c3f680a2ba1936a8c61d1af52a",
    "b7e21f416be09d2a8d64c3d3d8582968c2839902229f85aee297e717c094c8df",
    "4a23bb5db658dd377bf0f4ff3ffd8fba5e383a48574802ed545bbe7a6b475353",
    "3353d73706067640135a7ce517279cd683039747d218647c86e097b0daa2872d",
    "54b8f3e5085987629547b830d8118161b65079fe7bc59a99e9c3c7380e3e70b7",
    "138fe5d9be2551502b698d09ae193972f27d40f38dea264a0126e637d74ae4c9",
    "2a6249fa103436d3eb0d4029ac712bfc7a5eacbdd7518d6d4fe903a5ae65527c",
    "d65bb0d4e9925ca24fd7214dc617c150544e423f450c99ce51ac8005d33acd74",
    "f1bed3b17b7266a4a3bb86da7eba80b101e15cb79de9a207852cf91249ef4806",
    "19ff2af8cabca83125d1faa94cbb0a03a906f683b3f47a97c871fd513e510a7a",
    "25f283b196075778496152a91c2bf9da76ebe089f4654877f2d586ae7149c406",
    "e663eadeb2b5c7e82429b9e8cb4834c83464f079995332e4b3c8f5a72bb4b8c6",
    "f74b0d45dc6c1f79952c0b7420df525e37c15377b5f0984319c3993921e5ccd9",
    "7e097592064530d33de3afad5733cbe7703c5296263f77342efbf5a04755b0b3",
    "c997c4328463e84caa2de3ffdcd297baaaacd7ae646e44b5c0f16044df38fabd",
    "296a47b3a838a913982fb2e370c078edb042c84db34ce36b46ccb76460a690cc",
    "86c302457dd1cde197ec8075e82b393d542075134e2a17ee70a5e187075d03ae",
    "3c853cff60729ba4000000054de1f6965bdabc676c5a4dc7c35f97f82cb0e31c",
    "68d04f1dad96314ff09e6b3de96aeee300d1f68bf1bca9fc58e4032336cd819a",
    "af578744e50d1357a0e4286704d341aa0a337b19fe4bc43c2e79964d4f351089",
    "f2e0e41c7c43ae0d49e7f404b0f75be80ea3af098c9752420a8ac0ea2bbb1f4e",
    "eba05238aef0d8ce63f0c6e5e4041d95398a6f7f3e0ee97cc1591849d4ed2363",
    "38b147abde9f51ef9fd4e1c1",
];

// ---------------------------------------------------------------------------
// Positive vectors
// ---------------------------------------------------------------------------

use lms_verify::{
    signature_len, verify, Error, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H10,
    LMS_SHA256_M32_H5, PUBLIC_KEY_LEN,
};

#[test]
fn tc1_root_signature_over_the_level_1_public_key() {
    let pk = hex(TC1_PK_ROOT);
    let signed_message = hex(TC1_PK1);
    let sig = hex(TC1_SIG0);

    assert_eq!(pk.len(), PUBLIC_KEY_LEN);
    assert_eq!(
        sig.len(),
        signature_len(&LMOTS_SHA256_N32_W8, &LMS_SHA256_M32_H5)
    );
    assert_eq!(verify(&pk, &signed_message, &sig), Ok(()));
}

#[test]
fn tc1_level_1_signature_over_the_message() {
    let pk = hex(TC1_PK1);
    let msg = hex(TC1_MSG);
    let sig = hex(TC1_SIG1);

    assert_eq!(verify(&pk, &msg, &sig), Ok(()));
}

#[test]
fn tc2_root_signature_h10_w4() {
    let pk = hex(TC2_PK_ROOT);
    let signed_message = hex(TC2_PK1);
    let sig = hex(TC2_SIG0);

    // The parameter set the round-trip tests never reach: a height-10 tree with
    // 67 chains of 15 rather than 34 chains of 255.
    assert_eq!(
        sig.len(),
        signature_len(&LMOTS_SHA256_N32_W4, &LMS_SHA256_M32_H10)
    );
    assert_eq!(sig.len(), 2508);
    assert_eq!(verify(&pk, &signed_message, &sig), Ok(()));
}

#[test]
fn tc2_level_1_signature_over_the_message() {
    let pk = hex(TC2_PK1);
    let msg = hex(TC2_MSG);
    let sig = hex(TC2_SIG1);

    assert_eq!(verify(&pk, &msg, &sig), Ok(()));
}

// ---------------------------------------------------------------------------
// Negative vectors, all derived from the genuine ones
// ---------------------------------------------------------------------------

#[test]
fn a_flipped_bit_anywhere_in_the_signature_is_rejected() {
    let pk = hex(TC1_PK1);
    let msg = hex(TC1_MSG);
    let good = hex(TC1_SIG1);

    // One offset in each structural region: the randomiser C, the middle of the
    // hash chains, and the authentication path. Each reaches the root by a
    // different route, so a bug in one region cannot hide behind another.
    for &offset in &[8usize, 600, 1291] {
        let mut sig = good.clone();
        sig[offset] ^= 0x01;
        assert_eq!(
            verify(&pk, &msg, &sig),
            Err(Error::Invalid),
            "flipping bit 0 of byte {offset} was accepted"
        );
    }
}

#[test]
fn a_flipped_bit_in_the_message_is_rejected() {
    let pk = hex(TC1_PK1);
    let good = hex(TC1_MSG);
    let sig = hex(TC1_SIG1);

    let mut msg = good.clone();
    msg[0] ^= 0x01;
    assert_eq!(verify(&pk, &msg, &sig), Err(Error::Invalid));

    // Truncation counts as tampering: the message is hashed, not length-prefixed
    // by us, so a short read must not verify.
    assert_eq!(
        verify(&pk, &good[..good.len() - 1], &sig),
        Err(Error::Invalid)
    );
}

#[test]
fn a_signature_does_not_verify_under_the_wrong_key() {
    // Same parameter set, different tree: TC2's level-1 key is also H5/W8.
    let sig = hex(TC1_SIG1);
    let msg = hex(TC1_MSG);
    assert_eq!(verify(&hex(TC2_PK1), &msg, &sig), Err(Error::Invalid));
}

#[test]
fn the_two_signatures_of_one_test_case_are_not_interchangeable() {
    // sig[0] signs a public key and sig[1] signs the message. Swapping them must
    // fail even though both are well-formed signatures under the same scheme.
    let msg = hex(TC1_MSG);
    assert_eq!(
        verify(&hex(TC1_PK1), &msg, &hex(TC1_SIG0)),
        Err(Error::Invalid)
    );
}

#[test]
fn a_wrong_leaf_index_is_rejected_before_any_hashing() {
    let pk = hex(TC1_PK1);
    let msg = hex(TC1_MSG);
    let good = hex(TC1_SIG1);

    // Inside the tree but not the leaf that signed: the OTS chains no longer
    // produce a public key that hashes to the published root.
    let mut sig = good.clone();
    sig[0..4].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(verify(&pk, &msg, &sig), Err(Error::Invalid));

    // Outside the tree: caught by the bounds check, not by the hashing.
    let mut sig = good.clone();
    sig[0..4].copy_from_slice(&32u32.to_be_bytes());
    assert_eq!(verify(&pk, &msg, &sig), Err(Error::BadIndex));
}

#[test]
fn typecode_disagreement_is_reported_as_such() {
    let pk = hex(TC1_PK1);
    let msg = hex(TC1_MSG);
    let good = hex(TC1_SIG1);

    // The LMS typecode is repeated inside the signature; the two must agree.
    let mut sig = good.clone();
    let at = 4 + 4 + 32 * 35; // start of the trailing LMS typecode
    sig[at..at + 4].copy_from_slice(&6u32.to_be_bytes()); // H10 against an H5 key
    assert_eq!(verify(&pk, &msg, &sig), Err(Error::TypeMismatch));

    // An LM-OTS typecode nobody has defined.
    let mut bad_pk = pk.clone();
    bad_pk[4..8].copy_from_slice(&99u32.to_be_bytes());
    assert_eq!(verify(&bad_pk, &msg, &good), Err(Error::UnknownLmotsType));
}

#[test]
fn truncation_and_extension_are_rejected_as_length_errors() {
    let pk = hex(TC1_PK1);
    let msg = hex(TC1_MSG);
    let good = hex(TC1_SIG1);

    assert_eq!(
        verify(&pk, &msg, &good[..good.len() - 1]),
        Err(Error::BadLength)
    );

    let mut long = good.clone();
    long.push(0);
    assert_eq!(verify(&pk, &msg, &long), Err(Error::BadLength));

    // A public key of the wrong length, including the HSS-wrapped form that still
    // carries its four-byte `levels` prefix — the mistake this crate's own
    // vector extraction had to avoid.
    let mut hss_wrapped = vec![0, 0, 0, 2];
    hss_wrapped.extend_from_slice(&pk);
    assert_eq!(verify(&hss_wrapped, &msg, &good), Err(Error::BadLength));
}

#[test]
fn an_empty_message_verifies_against_nothing() {
    let pk = hex(TC1_PK1);
    assert_eq!(verify(&pk, b"", &hex(TC1_SIG1)), Err(Error::Invalid));
}

// ---------------------------------------------------------------------------
// The same vectors, as RFC 8554 actually publishes them
// ---------------------------------------------------------------------------
//
// Everything above takes the HSS test cases apart and checks the bare LMS
// signatures inside. That was necessary while the crate only did LMS, and it left
// one thing unchecked: the HSS framing itself — the `L` field, the `Nspk` field,
// and the rule that the two must agree.
//
// With `lms_verify::hss` in place the vectors can be used as published. The
// objects below are reassembled from the same constants rather than transcribed a
// second time, so there is no opportunity for the two forms to drift apart.

/// `u32str(L) || pub[0]`, RFC 8554 §6.1.
fn hss_public_key(levels: u32, root: &[&str]) -> Vec<u8> {
    let mut pk = levels.to_be_bytes().to_vec();
    pk.extend_from_slice(&hex(root));
    pk
}

/// `u32str(Nspk) || sig[0] || pub[1] || sig[1]`, RFC 8554 §6.2, for `Nspk = 1`.
fn hss_signature(sig0: &[&str], pub1: &[&str], sig1: &[&str]) -> Vec<u8> {
    let mut sig = 1u32.to_be_bytes().to_vec();
    sig.extend_from_slice(&hex(sig0));
    sig.extend_from_slice(&hex(pub1));
    sig.extend_from_slice(&hex(sig1));
    sig
}

#[test]
fn tc1_verifies_as_published_hss() {
    let pk = hss_public_key(2, TC1_PK_ROOT);
    let sig = hss_signature(TC1_SIG0, TC1_PK1, TC1_SIG1);
    assert_eq!(lms_verify::hss::verify(&pk, &hex(TC1_MSG), &sig), Ok(()));
    assert_eq!(lms_verify::hss::levels(&pk), Ok(2));
}

#[test]
fn tc2_verifies_as_published_hss() {
    // Mixed parameter sets across levels: an H10/W4 root over an H5/W8 child. The
    // verifier reads each level's parameters out of that level's own key, so this
    // is the case that catches an implementation which assumes one set throughout.
    let pk = hss_public_key(2, TC2_PK_ROOT);
    let sig = hss_signature(TC2_SIG0, TC2_PK1, TC2_SIG1);
    assert_eq!(lms_verify::hss::verify(&pk, &hex(TC2_MSG), &sig), Ok(()));
}

#[test]
fn the_published_vectors_do_not_cross_verify() {
    // TC1's signature under TC2's key and vice versa.
    //
    // These fail with `BadLength`, not `Invalid`, and the reason is worth recording
    // rather than papering over: the two test cases use different parameter sets at
    // the root — TC1 is H5/W8 with a 1292-byte signature, TC2 is H10/W4 with a
    // 2508-byte one. The parser reads the expected length from the *key* and
    // compares it against what the signature actually is, so the mismatch is caught
    // before a single hash is computed.
    //
    // That ordering is deliberate defence in depth. A verifier that fed a
    // wrong-length signature into the hashing loop and relied on the root
    // comparison to catch it would be doing arithmetic on attacker-controlled
    // lengths first, which is where buffer bugs live.
    let pk1 = hss_public_key(2, TC1_PK_ROOT);
    let pk2 = hss_public_key(2, TC2_PK_ROOT);
    let s1 = hss_signature(TC1_SIG0, TC1_PK1, TC1_SIG1);
    let s2 = hss_signature(TC2_SIG0, TC2_PK1, TC2_SIG1);

    assert_eq!(
        lms_verify::hss::verify(&pk2, &hex(TC1_MSG), &s1),
        Err(lms_verify::Error::BadLength)
    );
    assert_eq!(
        lms_verify::hss::verify(&pk1, &hex(TC2_MSG), &s2),
        Err(lms_verify::Error::BadLength)
    );

    // And the case where lengths *do* line up, so the rejection has to come from
    // the cryptography: TC2's level-1 key is H5/W8, the same shape as TC1's root.
    // Splice it in as the root of a one-level key and reuse TC1's final signature.
    let mut spliced = 1u32.to_be_bytes().to_vec();
    spliced.extend_from_slice(&hex(TC2_PK1));
    let mut lone = 0u32.to_be_bytes().to_vec(); // Nspk = 0, one level
    lone.extend_from_slice(&hex(TC1_SIG1));
    assert_eq!(
        lms_verify::hss::verify(&spliced, &hex(TC1_MSG), &lone),
        Err(lms_verify::Error::Invalid),
        "same shape, wrong key — this one must fail on the hash, not the length"
    );
}

#[test]
fn a_published_signature_will_not_verify_a_different_message() {
    let pk = hss_public_key(2, TC1_PK_ROOT);
    let sig = hss_signature(TC1_SIG0, TC1_PK1, TC1_SIG1);
    // The Ninth Amendment against a signature over the Tenth.
    assert_eq!(
        lms_verify::hss::verify(&pk, &hex(TC2_MSG), &sig),
        Err(lms_verify::Error::Invalid)
    );
}
