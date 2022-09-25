import * as bls from '..';
import { deepStrictEqual } from 'assert';
import { sha512 } from '@noble/hashes/sha512';

describe('hash_to_field', () => {
  const DST = 'QUUX-V01-CS02-with-expander-SHA256-128';
  const VECTORS = [
    {
      msg: '',
      len: 0x20,
      expected: '68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235',
    },
    {
      msg: 'abc',
      len: 0x20,
      expected: 'd8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x20,
      expected: 'eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x20,
      expected: 'b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x20,
      expected: '4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c',
    },
    {
      msg: '',
      len: 0x80,
      expected:
        'af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac0' +
        '6d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4' +
        'cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec8' +
        '49469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472' +
        'c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced',
    },
    {
      msg: 'abc',
      len: 0x80,
      expected:
        'abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2' +
        'fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b' +
        '664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221' +
        'b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425' +
        'cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x80,
      expected:
        'ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d6' +
        '29831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f' +
        '0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f8' +
        '7910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7d' +
        'e2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x80,
      expected:
        '80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a' +
        '5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169' +
        '761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b3' +
        '2286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520e' +
        'e603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x80,
      expected:
        '546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9' +
        'e75885cad9def1d06d6792f8a7d12794e90efed817d96920d72889' +
        '6a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4cee' +
        'f777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43' +
        'd98a294bebb9125d5b794e9d2a81181066eb954966a487',
    },
  ];
  for (let i = 0; i < VECTORS.length; i++) {
    const t = VECTORS[i];
    it(`expand_message_xmd(SHA-256) (${i})`, async () => {
      const p = await bls.utils.expandMessageXMD(
        bls.utils.stringToBytes(t.msg),
        bls.utils.stringToBytes(DST),
        t.len
      );
      deepStrictEqual(bls.utils.bytesToHex(p), t.expected);
    });
  }
  const LONG_DST =
    'QUUX-V01-CS02-with-expander-SHA256-128-long-DST-111111' +
    '111111111111111111111111111111111111111111111111111111' +
    '111111111111111111111111111111111111111111111111111111' +
    '111111111111111111111111111111111111111111111111111111' +
    '1111111111111111111111111111111111111111';
  const VECTORS_BIG = [
    {
      msg: '',
      len: 0x20,
      expected: 'e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3',
    },
    {
      msg: 'abc',
      len: 0x20,
      expected: '52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x20,
      expected: '35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x20,
      expected: '01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x20,
      expected: '20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b',
    },
    {
      msg: '',
      len: 0x80,
      expected:
        '14604d85432c68b757e485c8894db3117992fc57e0e136f7' +
        '1ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5ce4f' +
        '7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d' +
        '5edbd873f0eb35260145cd4e64f748c5dfe60567e126604bcab1a3' +
        'ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc',
    },
    {
      msg: 'abc',
      len: 0x80,
      expected:
        '1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d' +
        '0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853' +
        'e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794' +
        '727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee' +
        '4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x80,
      expected:
        'd2ecef3635d2397f34a9f86438d772db19ffe9924e28a1ca' +
        'f6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33a424' +
        '9206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d' +
        '7027ed3774512ef5b00d816e51bfcc96c3539601fa48ef1c07e494' +
        'bdc37054ba96ecb9dbd666417e3de289d4f424f502a982',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x80,
      expected:
        'ed6e8c036df90111410431431a232d41a32c86e296c05d42' +
        '6e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9180d' +
        '0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c' +
        '50e3a83316783b649e5ecc9d3b1d9471cb5024b7ccf40d41d1751a' +
        '04ca0356548bc6e703fca02ab521b505e8e45600508d32',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x80,
      expected:
        '78b53f2413f3c688f07732c10e5ced29a17c6a16f717179f' +
        'fbe38d92d6c9ec296502eb9889af83a1928cd162e845b0d3c5424e' +
        '83280fed3d10cffb2f8431f14e7a23f4c68819d40617589e4c4116' +
        '9d0b56e0e3535be1fd71fbb08bb70c5b5ffed953d6c14bf7618b35' +
        'fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495',
    },
  ];
  for (let i = 0; i < VECTORS_BIG.length; i++) {
    const t = VECTORS_BIG[i];
    it(`expand_message_xmd(SHA-256) (long DST) (${i})`, async () => {
      const p = await bls.utils.expandMessageXMD(
        bls.utils.stringToBytes(t.msg),
        bls.utils.stringToBytes(LONG_DST),
        t.len
      );
      deepStrictEqual(bls.utils.bytesToHex(p), t.expected);
    });
  }
  const DST_512 = 'QUUX-V01-CS02-with-expander-SHA512-256';
  const VECTORS_SHA512 = [
    {
      msg: '',
      len: 0x20,
      expected: '6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba',
    },
    {
      msg: 'abc',
      len: 0x20,
      expected: '0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x20,
      expected: '087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x20,
      expected: '7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x20,
      expected: '57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4',
    },
    {
      msg: '',
      len: 0x80,
      expected:
        '41b037d1734a5f8df225dd8c7de38f851efdb45c372887be' +
        '655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebb' +
        'bec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f' +
        '098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da6' +
        '78b318bd0e65ebff70bec88c753b159a805d2c89c55961',
    },
    {
      msg: 'abc',
      len: 0x80,
      expected:
        '7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c178' +
        '6d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb4521713' +
        '5456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043e' +
        'd2901bce7f22610c0419751c065922b488431851041310ad659e4b' +
        '23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x80,
      expected:
        '3f721f208e6199fe903545abc26c837ce59ac6fa45733f1b' +
        'aaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae6' +
        '12ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd069301' +
        '6af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed' +
        '0d35c3f1023d64ad1407924288d366ea159f46287e61ac',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x80,
      expected:
        'b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd' +
        '12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703' +
        'dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a2' +
        '58e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9' +
        'a1422949471d267b21bc88e688e4014087a0b592b695ed',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x80,
      expected:
        '05b0bfef265dcee87654372777b7c44177e2ae4c13a27f10' +
        '3340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a' +
        '1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46' +
        'daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5' +
        '197fefc571a92929c9084ffe1112cf5eea5192ebff330b',
    },
  ];
  for (let i = 0; i < VECTORS_SHA512.length; i++) {
    const t = VECTORS_SHA512[i];
    it(`expand_message_xmd(SHA-256) (long DST) (${i})`, async () => {
      const p = await bls.utils.expandMessageXMD(
        bls.utils.stringToBytes(t.msg),
        bls.utils.stringToBytes(DST_512),
        t.len,
        sha512
      );
      deepStrictEqual(bls.utils.bytesToHex(p), t.expected);
    });
  }
});
describe('hashToCurve', () => {
  // Point G1
  const VECTORS_G1 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '0576730ab036cbac1d95b38dca905586f28d0a59048db4e8778782d89bff856ddef89277ead5a21e2975c4a6e3d8c79e' +
        '1273e568bebf1864393c517f999b87c1eaa1b8432f95aea8160cd981b5b05d8cd4a7cf00103b6ef87f728e4b547dd7ae',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '061daf0cc00d8912dac1d4cf5a7c32fca97f8b3bf3f805121888e5eb89f77f9a9f406569027ac6d0e61b1229f42c43d6' +
        '0de1601e5ba02cb637c1d35266f5700acee9850796dc88e860d022d7b9e7e3dce5950952e97861e5bb16d215c87f030d',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '0fb3455436843e76079c7cf3dfef75e5a104dfe257a29a850c145568d500ad31ccfe79be9ae0ea31a722548070cf98cd' +
        '177989f7e2c751658df1b26943ee829d3ebcf131d8f805571712f3a7527ee5334ecff8a97fc2a50cea86f5e6212e9a57',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '0514af2137c1ae1d78d5cb97ee606ea142824c199f0f25ac463a0c78200de57640d34686521d3e9cf6b3721834f8a038' +
        '047a85d6898416a0899e26219bca7c4f0fa682717199de196b02b95eaf9fb55456ac3b810e78571a1b7f5692b7c58ab6',
    },
  ];
  for (let i = 0; i < VECTORS_G1.length; i++) {
    const t = VECTORS_G1[i];
    it(`G1 Killic (${i})`, async () => {
      const p = await bls.PointG1.hashToCurve(t.msg, {
        DST: 'BLS12381G1_XMD:SHA-256_SSWU_RO_TESTGEN',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
  const VECTORS_G1_RO = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1' +
        '08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903' +
        '0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98' +
        '03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488' +
        '1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe' +
        '05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8',
    },
  ];
  for (let i = 0; i < VECTORS_G1_RO.length; i++) {
    const t = VECTORS_G1_RO[i];
    it(`G1 (BLS12381G1_XMD:SHA-256_SSWU_RO_) (${i})`, async () => {
      const p = await bls.PointG1.hashToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
  const VECTORS_G1_NU = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba' +
        '04407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d' +
        '1532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '1974dbb8e6b5d20b84df7e625e2fbfecb2cdb5f77d5eae5fb2955e5ce7313cae8364bc2fff520a6c25619739c6bdcb6a' +
        '15f9897e11c6441eaa676de141c8d83c37aab8667173cbe1dfd6de74d11861b961dccebcd9d289ac633455dfcc7013a3',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '0a7a047c4a8397b3446450642c2ac64d7239b61872c9ae7a59707a8f4f950f101e766afe58223b3bff3a19a7f754027c' +
        '1383aebba1e4327ccff7cf9912bda0dbc77de048b71ef8c8a81111d71dc33c5e3aa6edee9cf6f5fe525d50cc50b77cc9',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '0e7a16a975904f131682edbb03d9560d3e48214c9986bd50417a77108d13dc957500edf96462a3d01e62dc6cd468ef11' +
        '0ae89e677711d05c30a48d6d75e76ca9fb70fe06c6dd6ff988683d89ccde29ac7d46c53bb97a59b1901abf1db66052db',
    },
  ];
  for (let i = 0; i < VECTORS_G1_NU.length; i++) {
    const t = VECTORS_G1_NU[i];
    it(`G1 (BLS12381G1_XMD:SHA-256_SSWU_NU_) (${i})`, async () => {
      const p = await bls.PointG1.encodeToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
  const VECTORS_ENCODE_G1 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '1223effdbb2d38152495a864d78eee14cb0992d89a241707abb03819a91a6d2fd65854ab9a69e9aacb0cbebfd490732c' +
        '0f925d61e0b235ecd945cbf0309291878df0d06e5d80d6b84aa4ff3e00633b26f9a7cb3523ef737d90e6d71e8b98b2d5',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '179d3fd0b4fb1da43aad06cea1fb3f828806ddb1b1fa9424b1e3944dfdbab6e763c42636404017da03099af0dcca0fd6' +
        '0d037cb1c6d495c0f5f22b061d23f1be3d7fe64d3c6820cfcd99b6b36fa69f7b4c1f4addba2ae7aa46fb25901ab483e4',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '15aa66c77eded1209db694e8b1ba49daf8b686733afaa7b68c683d0b01788dfb0617a2e2d04c0856db4981921d3004af' +
        '0952bb2f61739dd1d201dd0a79d74cda3285403d47655ee886afe860593a8a4e51c5b77a22d2133e3a4280eaaaa8b788',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '06328ce5106e837935e8da84bd9af473422e62492930aa5f460369baad9545defa468d9399854c23a75495d2a80487ee' +
        '094bfdfe3e552447433b5a00967498a3f1314b86ce7a7164c8a8f4131f99333b30a574607e301d5f774172c627fd0bca',
    },
  ];
  for (let i = 0; i < VECTORS_ENCODE_G1.length; i++) {
    const t = VECTORS_ENCODE_G1[i];
    it(`G1 (Killic, encodeToCurve) (${i})`, async () => {
      const p = await bls.PointG1.encodeToCurve(t.msg, {
        DST: 'BLS12381G1_XMD:SHA-256_SSWU_NU_TESTGEN',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
  // Point G2
  const VECTORS_G2 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '0fbdae26f9f9586a46d4b0b70390d09064ef2afe5c99348438a3c7d9756471e015cb534204c1b6824617a85024c772dc' +
        '0a650bd36ae7455cb3fe5d8bb1310594551456f5c6593aec9ee0c03d2f6cb693bd2c5e99d4e23cbaec767609314f51d3' +
        '02e5cf8f9b7348428cc9e66b9a9b36fe45ba0b0a146290c3a68d92895b1af0e1f2d9f889fb412670ae8478d8abd4c5aa' +
        '0d8d49e7737d8f9fc5cef7c4b8817633103faf2613016cb86a1f3fc29968fe2413e232d9208d2d74a89bf7a48ac36f83',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '03578447618463deb106b60e609c6f7cc446dc6035f84a72801ba17c94cd800583b493b948eff0033f09086fdd7f6175' +
        '1953ce6d4267939c7360756d9cca8eb34aac4633ef35369a7dc249445069888e7d1b3f9d2e75fbd468fbcbba7110ea02' +
        '0184d26779ae9d4670aca9b267dbd4d3b30443ad05b8546d36a195686e1ccc3a59194aea05ed5bce7c3144a29ec047c4' +
        '0882ab045b8fe4d7d557ebb59a63a35ac9f3d312581b509af0f8eaa2960cbc5e1e36bb969b6e22980b5cbdd0787fcf4e',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '195fad48982e186ce3c5c82133aefc9b26d55979b6f530992a8849d4263ec5d57f7a181553c8799bcc83da44847bdc8d' +
        '17b461fc3b96a30c2408958cbfa5f5927b6063a8ad199d5ebf2d7cdeffa9c20c85487204804fab53f950b2f87db365aa' +
        '005cdf3d984e3391e7e969276fb4bc02323c5924a4449af167030d855acc2600cf3d4fab025432c6d868c79571a95bef' +
        '174a3473a3af2d0302b9065e895ca4adba4ece6ce0b41148ba597001abb152f852dd9a96fb45c9de0a43d944746f833e',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '123b6bd9feeba26dd4ad00f8bfda2718c9700dc093ea5287d7711844644eb981848316d3f3f57d5d3a652c6cdc816aca' +
        '0a162306f3b0f2bb326f0c4fb0e1fea020019c3af796dcd1d7264f50ddae94cacf3cade74603834d44b9ab3d5d0a6c98' +
        '05483f3b96d9252dd4fc0868344dfaf3c9d145e3387db23fa8e449304fab6a7b6ec9c15f05c0a1ea66ff0efcc03e001a' +
        '15c1d4f1a685bb63ee67ca1fd96155e3d091e852a684b78d085fd34f6091e5249ddddbdcf2e7ec82ce6c04c63647eeb7',
    },
  ];
  for (let i = 0; i < VECTORS_G2.length; i++) {
    const t = VECTORS_G2[i];
    it(`G2 Killic (${i})`, async () => {
      const p = await bls.PointG2.hashToCurve(t.msg, {
        DST: 'BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
  const VECTORS_G2_RO = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d' +
        '0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a' +
        '12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6' +
        '0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8' +
        '02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6' +
        '00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16' +
        '1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c' +
        '121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0' +
        '0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be' +
        '05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91' +
        '19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da' +
        '09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662' +
        '14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569' +
        '01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534' +
        '03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52' +
        '0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e',
    },
  ];
  for (let i = 0; i < VECTORS_G2_RO.length; i++) {
    const t = VECTORS_G2_RO[i];
    it(`G2 (BLS12381G2_XMD:SHA-256_SSWU_RO_) (${i})`, async () => {
      const p = await bls.PointG2.hashToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
  const VECTORS_G2_NU = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '126b855e9e69b1f691f816e48ac6977664d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b' +
        '00e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb7' +
        '1498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d' +
        '0caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '0296238ea82c6d4adb3c838ee3cb2346049c90b96d602d7bb1b469b905c9228be25c627bffee872def773d5b2a2eb57d' +
        '108ed59fd9fae381abfd1d6bce2fd2fa220990f0f837fa30e0f27914ed6e1454db0d1ee957b219f61da6ff8be0d6441f' +
        '153606c417e59fb331b7ae6bce4fbf7c5190c33ce9402b5ebe2b70e44fca614f3f1382a3625ed5493843d0b0a652fc3f' +
        '033f90f6057aadacae7963b0a0b379dd46750c1c94a6357c99b65f63b79e321ff50fe3053330911c56b6ceea08fee656',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '0da75be60fb6aa0e9e3143e40c42796edf15685cafe0279afd2a67c3dff1c82341f17effd402e4f1af240ea90f4b659b' +
        '038af300ef34c7759a6caaa4e69363cafeed218a1f207e93b2c70d91a1263d375d6730bd6b6509dcac3ba5b567e85bf3' +
        '0492f4fed741b073e5a82580f7c663f9b79e036b70ab3e51162359cec4e77c78086fe879b65ca7a47d34374c8315ac5e' +
        '19b148cbdf163cf0894f29660d2e7bfb2b68e37d54cc83fd4e6e62c020eaa48709302ef8e746736c0e19342cc1ce3df4',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '12c8c05c1d5fc7bfa847f4d7d81e294e66b9a78bc9953990c358945e1f042eedafce608b67fdd3ab0cb2e6e263b9b1ad' +
        '0c5ae723be00e6c3f0efe184fdc0702b64588fe77dda152ab13099a3bacd3876767fa7bbad6d6fd90b3642e902b208f9' +
        '11c624c56dbe154d759d021eec60fab3d8b852395a89de497e48504366feedd4662d023af447d66926a28076813dd646' +
        '04e77ddb3ede41b5ec4396b7421dd916efc68a358a0d7425bddd253547f2fb4830522358491827265dfc5bcc1928a569',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '1565c2f625032d232f13121d3cfb476f45275c303a037faa255f9da62000c2c864ea881e2bcddd111edc4a3c0da3e88d' +
        '0ea4e7c33d43e17cc516a72f76437c4bf81d8f4eac69ac355d3bf9b71b8138d55dc10fd458be115afa798b55dac34be1' +
        '0f8991d2a1ad662e7b6f58ab787947f1fa607fce12dde171bc17903b012091b657e15333e11701edcf5b63ba2a561247' +
        '043b6f5fe4e52c839148dc66f2b3751e69a0f6ebb3d056d6465d50d4108543ecd956e10fa1640dfd9bc0030cc2558d28',
    },
  ];
  for (let i = 0; i < VECTORS_G2_NU.length; i++) {
    const t = VECTORS_G2_NU[i];
    it(`G2 (BLS12381G2_XMD:SHA-256_SSWU_NU_) (${i})`, async () => {
      const p = await bls.PointG2.encodeToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_NU_',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
  const VECTORS_ENCODE_G2 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '0d4333b77becbf9f9dfa3ca928002233d1ecc854b1447e5a71f751c9042d000f42db91c1d6649a5e0ad22bd7bf7398b8' +
        '027e4bfada0b47f9f07e04aec463c7371e68f2fd0c738cd517932ea3801a35acf09db018deda57387b0f270f7a219e4d' +
        '0cc76dc777ea0d447e02a41004f37a0a7b1fafb6746884e8d9fc276716ccf47e4e0899548a2ec71c2bdf1a2a50e876db' +
        '053674cba9ef516ddc218fedb37324e6c47de27f88ab7ef123b006127d738293c0277187f7e2f80a299a24d84ed03da7',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '18f0f87b40af67c056915dbaf48534c592524e82c1c2b50c3734d02c0172c80df780a60b5683759298a3303c5d942778' +
        '09349f1cb5b2e55489dcd45a38545343451cc30a1681c57acd4fb0a6db125f8352c09f4a67eb7d1d8242cb7d3405f97b' +
        '10a2ba341bc689ab947b7941ce6ef39be17acaab067bd32bd652b471ab0792c53a2bd03bdac47f96aaafe96e441f63c0' +
        '02f2d9deb2c7742512f5b8230bf0fd83ea42279d7d39779543c1a43b61c885982b611f6a7a24b514995e8a098496b811',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '19808ec5930a53c7cf5912ccce1cc33f1b3dcff24a53ce1cc4cba41fd6996dbed4843ccdd2eaf6a0cd801e562718d163' +
        '149fe43777d34f0d25430dea463889bd9393bdfb4932946db23671727081c629ebb98a89604f3433fba1c67d356a4af7' +
        '04783e391c30c83f805ca271e353582fdf19d159f6a4c39b73acbb637a9b8ac820cfbe2738d683368a7c07ad020e3e33' +
        '04c0d6793a766233b2982087b5f4a254f261003ccb3262ea7c50903eecef3e871d1502c293f9e063d7d293f6384f4551',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '0b8e0094c886487870372eb6264613a6a087c7eb9804fab789be4e47a57b29eb19b1983a51165a1b5eb025865e9fc63a' +
        '0804152cbf8474669ad7d1796ab92d7ca21f32d8bed70898a748ed4e4e0ec557069003732fc86866d938538a2ae95552' +
        '14c80f068ece15a3936bb00c3c883966f75b4e8d9ddde809c11f781ab92d23a2d1d103ad48f6f3bb158bf3e3a4063449' +
        '09e5c8242dd7281ad32c03fe4af3f19167770016255fb25ad9b67ec51d62fade31a1af101e8f6172ec2ee8857662be3a',
    },
  ];
  for (let i = 0; i < VECTORS_ENCODE_G2.length; i++) {
    const t = VECTORS_ENCODE_G2[i];
    it(`G2 (Killic, encodeToCurve) (${i})`, async () => {
      const p = await bls.PointG2.encodeToCurve(t.msg, {
        DST: 'BLS12381G2_XMD:SHA-256_SSWU_NU_TESTGEN',
      });
      deepStrictEqual(p.toHex(), t.expected);
    });
  }
});
