const chai = require('chai');
const fluxsdk = require('../lib');

const { expect } = chai;

it('FluxNode - calculate FluxNode Public Key', () => {
  const privateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
  const publicKey = fluxsdk.fluxnode.getFluxNodePublicKey(privateKey);
  expect(publicKey).to.equal('04f6c04f8a3569a518ec0987fc2544900e8a3f742a6e0d891a700d9a94482a0abdae64a1c106a4d4339963afd32391e0e660fabbc75c73200fc863287cfd54a7f2');
});

it('FluxNode - calculate Collateral Public Key', () => {
  const privateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
  const publicKey = fluxsdk.fluxnode.getCollateralPublicKey(privateKey);
  expect(publicKey).to.equal('03c7f8f9e5368a2bee1ba3b3127b5039f84e8f1dad0e11f64e5586b76f654ee2a3');
});

it('FluxNode - create start transaction', () => {
  const collateralOutHash = '99ae0a75182e48fe82d64b5fc5b238dd79d045382ea7688d38f0b777bb2dbd44';
  const collateralOutIndex = '0'; // string
  const collateralPrivateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
  const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
  const timestamp = '1584866597'; // in seconds
  const tx = fluxsdk.fluxnode.startFluxNode(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp);
  expect(tx).to.equal('050000000244bd2dbb77b7f0388d68a72e3845d079dd38b2c55f4bd682fe482e18750aae99000000002103c7f8f9e5368a2bee1ba3b3127b5039f84e8f1dad0e11f64e5586b76f654ee2a34104f6c04f8a3569a518ec0987fc2544900e8a3f742a6e0d891a700d9a94482a0abdae64a1c106a4d4339963afd32391e0e660fabbc75c73200fc863287cfd54a7f22525775e4120556a2ebcbdab6cc332b14996c1e0a996810a0cd6a80cd044020b04a4466dee0e67b8bc2f21fe2e1eb7d093594c2601e679750aa8a9c4eb68a21575c34e4aa082');
});

it('FluxNode - sign message', () => {
  const msg = '050000000244bd2dbb77b7f0388d68a72e3845d079dd38b2c55f4bd682fe482e18750aae99000000002103c7f8f9e5368a2bee1ba3b3127b5039f84e8f1dad0e11f64e5586b76f654ee2a34104f6c04f8a3569a518ec0987fc2544900e8a3f742a6e0d891a700d9a94482a0abdae64a1c106a4d4339963afd32391e0e660fabbc75c73200fc863287cfd54a7f22525775e4120556a2ebcbdab6cc332b14996c1e0a996810a0cd6a80cd044020b04a4466dee0e67b8bc2f21fe2e1eb7d093594c2601e679750aa8a9c4eb68a21575c34e4aa082';
  const privateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
  const signature = fluxsdk.fluxnode.signMessage(msg, privateKey);
  expect(signature).to.equal('Hwwod9fKqEGZr8W5m3keUOWgDW6jhlZlr4VsNq2DvSEXHYQCBSsceJ7/uNqw7nUlBd0bi4UjFS+gmVLX9Ipe7+A=');
});

it('FluxNode - sign Start message', () => {
  const msg = '050000000244bd2dbb77b7f0388d68a72e3845d079dd38b2c55f4bd682fe482e18750aae99000000002103c7f8f9e5368a2bee1ba3b3127b5039f84e8f1dad0e11f64e5586b76f654ee2a34104f6c04f8a3569a518ec0987fc2544900e8a3f742a6e0d891a700d9a94482a0abdae64a1c106a4d4339963afd32391e0e660fabbc75c73200fc863287cfd54a7f22525775e';
  const privateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
  const signature = fluxsdk.fluxnode.signStartMessage(msg, privateKey);
  expect(signature).to.equal('20556a2ebcbdab6cc332b14996c1e0a996810a0cd6a80cd044020b04a4466dee0e67b8bc2f21fe2e1eb7d093594c2601e679750aa8a9c4eb68a21575c34e4aa082');
});

it('doubleHash', () => {
  const msg = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d014dffffffff0100f2052a01000000434104e70a02f5af48a1989bf630d92523c9d14c45c75f7d1b998e962bff6ff9995fc5bdb44f1793b37495d80324acba7c8f537caaf8432b8d47987313060cc82d8a93ac00000000';
  const hash = fluxsdk.fluxnode.doubleHash(msg);
  expect(hash).to.equal('660802c98f18fd34fd16d61c63cf447568370124ac5f3be626c2e1c3c9f0052d');
});

// start tx is not having signature
it('FluxNode - Create TXID from FluxNode start tx', () => {
  const msg = '0500000002b3ae41c6046000fd129425d08fd2142fc886cf2aea8d43a6951fc770e22cf914000000002103ffbec8caa95c594c574fa486b8540551dabdfa7aa86c3261b73bc96af32ab7a741047d88ba7d428352c09b402e84344dea5afb0ae8f7602893ab74804d1f7a7fb08e61857dac35012eb3b0c4ba603b38fd9575b92a53d1410fb5bdac38687998e35c2f00735e411f0d124251bb4751f573e80a66c84040cc3a5224ca3ba88a4a238f2cad85df98e47e42fe598b5c2dc07bff6d699cd67fc869a1a8e7da6b4fadbdd7287837602b85';
  const hash = fluxsdk.fluxnode.txidStart(msg);
  expect(hash).to.equal('a89fcfa77810e5b6bae6a4be065d8db9f0aa7a11bedce37b9ddf91372fe0fa4e');
});

// Confirm tx is not having both signatures
it('Create transaction ID from FluxNode confirm tx', () => {
  const msg = '0500000004b3ae41c6046000fd129425d08fd2142fc886cf2aea8d43a6951fc770e22cf9140000000092e0915e0221dc915e010b3134342e39312e39372e37411c5c7481be62ae34064e2984eb541782bdbb7c35885cf5ac9c5faeef4e73be00a0528d8faa73a246271dd6846bb7d15c719ff83b8d2321e88feb26a6562e58ed55411bd1abef6bda91d48cbbae41e0aba2f7d8cd676e7b721ed05bd5535bffc82dc93d4038807f50a0f0bffb22c6e28acf684ea5b4974f38940290037af93f76c91142';
  const hash = fluxsdk.fluxnode.txidConfirm(msg);
  expect(hash).to.equal('9c4dcbd1eab60e969207c90ed0e3ad8f6f8913372b255dc967a2cdbeeccebf3e');
});

it('FluxNode - create start transaction v6', () => {
  const collateralOutHash = 'e7e55985d4836edd7e664af167e8f729f021b1728ef121af3f5f02ae7ad1a686';
  const collateralOutIndex = '0'; // string
  const collateralPrivateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
  const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
  const timestamp = '1698521898'; // in seconds
  const tx = fluxsdk.fluxnode.startFluxNodev6(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp);
  expect(tx).to.equal('06000000020100000086a6d17aae025f3faf21f18e72b121f029f7e867f14a667edd6e83d48559e5e7000000002103c7f8f9e5368a2bee1ba3b3127b5039f84e8f1dad0e11f64e5586b76f654ee2a34104f6c04f8a3569a518ec0987fc2544900e8a3f742a6e0d891a700d9a94482a0abdae64a1c106a4d4339963afd32391e0e660fabbc75c73200fc863287cfd54a7f22a633d65411f0aa8ef1c0aeab2fc379adae674e6e41838cbadaa0db513b4df06515f3466fb40642fb91980644758f4ddab66eeb5751b5c72efcb79250754d2e01539f7bba787');
});

it('FluxNode - create start transaction v6 P2SH', () => {
  const collateralOutHash = 'a373395cc26af216ee9885282d2f7bf8317c4e6f02f1561d1d6f46ba9cc86a71';
  const collateralOutIndex = '0'; // string
  const collateralPrivateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
  const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
  const timestamp = '1698522999'; // in seconds
  const redeemScript = '5221022180e3478446c3d8967bac969bc0a55ac094d28a479973bccc88c495fa576f9d2103abfa98505a1423498287e160a96163b6a1aa844fd7879c6263f1bd0e077e33f552ae';
  const tx = fluxsdk.fluxnode.startFluxNodev6(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp, true, false, redeemScript);
  expect(tx).to.equal('060000000202000000716ac89cba466f1d1d56f1026f4e7c31f87b2f2d288598ee16f26ac25c3973a3000000004104f6c04f8a3569a518ec0987fc2544900e8a3f742a6e0d891a700d9a94482a0abdae64a1c106a4d4339963afd32391e0e660fabbc75c73200fc863287cfd54a7f2475221022180e3478446c3d8967bac969bc0a55ac094d28a479973bccc88c495fa576f9d2103abfa98505a1423498287e160a96163b6a1aa844fd7879c6263f1bd0e077e33f552ae77673d65411ffbfdd06c639a65fc782836d9a7ad9d05a1ac3b35b7fecf591e3e6e355e067b774171fa62d79d632942524442ea08f896f512ba15400c83190886f109ebb684d0');
});

// =================== DELEGATE TESTS ===================

describe('FluxNode Delegate Features', () => {
  it('FluxNode - startFluxNodeAddDelegate with single delegate', () => {
    const collateralOutHash = '99ae0a75182e48fe82d64b5fc5b238dd79d045382ea7688d38f0b777bb2dbd44';
    const collateralOutIndex = '0';
    const collateralPrivateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
    const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
    const timestamp = '1698522999';

    // Test delegate public key (compressed, 33 bytes)
    const delegatePublicKeys = ['0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'];

    const tx = fluxsdk.fluxnode.startFluxNodeAddDelegate(
      collateralOutHash,
      collateralOutIndex,
      collateralPrivateKey,
      fluxnodePrivateKey,
      timestamp,
      delegatePublicKeys,
    );

    // The transaction should contain the delegate data serialized at the end
    expect(tx).to.be.a('string');
    expect(tx.length).to.be.greaterThan(0);
    // Version 6, type 2, nFluxTxVersion with delegates (0x0101), then collateral hash
    // Delegate data: 01 (version), 01 (type UPDATE), 01 (num keys), 21 (33 bytes length), then pubkey
    expect(tx.includes('01010101210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')).to.equal(true);
  });

  it('FluxNode - startFluxNodeAddDelegate with multiple delegates', () => {
    const collateralOutHash = '99ae0a75182e48fe82d64b5fc5b238dd79d045382ea7688d38f0b777bb2dbd44';
    const collateralOutIndex = '1';
    const collateralPrivateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
    const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
    const timestamp = '1698523000';

    // Multiple delegate public keys (up to 4 allowed)
    const delegatePublicKeys = [
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
      '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
    ];

    const tx = fluxsdk.fluxnode.startFluxNodeAddDelegate(
      collateralOutHash,
      collateralOutIndex,
      collateralPrivateKey,
      fluxnodePrivateKey,
      timestamp,
      delegatePublicKeys,
    );

    expect(tx).to.be.a('string');
    expect(tx.length).to.be.greaterThan(0);
  });

  it('FluxNode - startFluxNodeAddDelegate validation errors', () => {
    const collateralOutHash = '99ae0a75182e48fe82d64b5fc5b238dd79d045382ea7688d38f0b777bb2dbd44';
    const collateralOutIndex = '0';
    const collateralPrivateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
    const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
    const timestamp = '1698522999';

    // Test with no delegates (should throw)
    expect(() => {
      fluxsdk.fluxnode.startFluxNodeAddDelegate(
        collateralOutHash,
        collateralOutIndex,
        collateralPrivateKey,
        fluxnodePrivateKey,
        timestamp,
        [],
      );
    }).to.throw('At least one delegate public key must be provided');

    // Test with invalid public key format
    expect(() => {
      fluxsdk.fluxnode.startFluxNodeAddDelegate(
        collateralOutHash,
        collateralOutIndex,
        collateralPrivateKey,
        fluxnodePrivateKey,
        timestamp,
        ['invalid_key'],
      );
    }).to.throw('Invalid delegate public key format');

    // Test with too many delegates (more than 4)
    expect(() => {
      const tooManyDelegates = [
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
        '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
        '03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7',
        '0388eb0e87ceecd650faa4d6dc90083c651a561a20da2dd2ec23ad70b973c23259',
      ];
      fluxsdk.fluxnode.startFluxNodeAddDelegate(
        collateralOutHash,
        collateralOutIndex,
        collateralPrivateKey,
        fluxnodePrivateKey,
        timestamp,
        tooManyDelegates,
      );
    }).to.throw('Too many delegate public keys. Maximum is 4');
  });

  it('FluxNode - startFluxNodeAddDelegate with P2SH', () => {
    const collateralOutHash = 'a373395cc26af216ee9885282d2f7bf8317c4e6f02f1561d1d6f46ba9cc86a71';
    const collateralOutIndex = '0';
    const collateralPrivateKey = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
    const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
    const timestamp = '1698522999';
    const redeemScript = '5221022180e3478446c3d8967bac969bc0a55ac094d28a479973bccc88c495fa576f9d2103abfa98505a1423498287e160a96163b6a1aa844fd7879c6263f1bd0e077e33f552ae';
    const delegatePublicKeys = ['0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'];

    const tx = fluxsdk.fluxnode.startFluxNodeAddDelegate(
      collateralOutHash,
      collateralOutIndex,
      collateralPrivateKey,
      fluxnodePrivateKey,
      timestamp,
      delegatePublicKeys,
      true,
      false,
      redeemScript,
    );

    expect(tx).to.be.a('string');
    expect(tx.length).to.be.greaterThan(0);
    // Should have P2SH version bits set (0x02) and delegates feature bit (0x0100)
    expect(tx.includes('02010000')).to.equal(true);
    // Verify delegate data is included (with CompactSize length prefix for CPubKey)
    expect(tx.includes('01010101210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')).to.equal(true);
  });

  it('FluxNode - startFluxNodeAsDelegate', () => {
    const collateralOutHash = '99ae0a75182e48fe82d64b5fc5b238dd79d045382ea7688d38f0b777bb2dbd44';
    const collateralOutIndex = '0';
    // Using a delegate's private key instead of collateral owner's key
    const delegatePrivateKey = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';
    const fluxnodePrivateKey = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
    const timestamp = '1698523001';

    const tx = fluxsdk.fluxnode.startFluxNodeAsDelegate(
      collateralOutHash,
      collateralOutIndex,
      delegatePrivateKey,
      fluxnodePrivateKey,
      timestamp,
    );

    expect(tx).to.be.a('string');
    expect(tx.length).to.be.greaterThan(0);
    // Should contain delegate data with type 2 (SIGNING)
    expect(tx.includes('010102')).to.equal(true); // version 1, type 2, no keys for SIGNING type
  });

  it('FluxNode - createDelegateData helper', () => {
    // Test UPDATE type with public keys
    const updateData = fluxsdk.fluxnode.createDelegateData(
      fluxsdk.fluxnode.DELEGATE_TYPE_UPDATE,
      ['0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
    );
    expect(updateData).to.deep.equal({
      version: 1,
      type: 1,
      delegatePublicKeys: ['0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
    });

    // Test SIGNING type
    const signingData = fluxsdk.fluxnode.createDelegateData(
      fluxsdk.fluxnode.DELEGATE_TYPE_SIGNING,
    );
    expect(signingData).to.deep.equal({
      version: 1,
      type: 2,
    });

    // Test NONE type
    const noneData = fluxsdk.fluxnode.createDelegateData(
      fluxsdk.fluxnode.DELEGATE_TYPE_NONE,
    );
    expect(noneData).to.deep.equal({
      version: 1,
      type: 0,
    });

    // Test UPDATE with private keys (should convert to public keys)
    const updateWithPrivKeys = fluxsdk.fluxnode.createDelegateData(
      fluxsdk.fluxnode.DELEGATE_TYPE_UPDATE,
      null,
      ['KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'],
    );
    expect(updateWithPrivKeys.delegatePublicKeys).to.be.an('array');
    expect(updateWithPrivKeys.delegatePublicKeys[0]).to.have.lengthOf(66);
  });

  it('FluxNode - convertDelegatePrivateKeysToPublic', () => {
    const privateKeys = [
      'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
      'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF',
    ];

    const publicKeys = fluxsdk.fluxnode.convertDelegatePrivateKeysToPublic(privateKeys);

    expect(publicKeys).to.be.an('array');
    expect(publicKeys).to.have.lengthOf(2);
    expect(publicKeys[0]).to.have.lengthOf(66); // Compressed public key
    expect(publicKeys[1]).to.have.lengthOf(66);
    expect(publicKeys[0].startsWith('02') || publicKeys[0].startsWith('03')).to.equal(true);
    expect(publicKeys[1].startsWith('02') || publicKeys[1].startsWith('03')).to.equal(true);
  });

  it('FluxNode - getPublicKeyFromPrivateKey', () => {
    const privateKey = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';

    // Test compressed
    const compressedPubKey = fluxsdk.fluxnode.getPublicKeyFromPrivateKey(privateKey, true);
    expect(compressedPubKey).to.have.lengthOf(66);
    expect(compressedPubKey.startsWith('02') || compressedPubKey.startsWith('03')).to.equal(true);

    // Test uncompressed
    const uncompressedPubKey = fluxsdk.fluxnode.getPublicKeyFromPrivateKey(privateKey, false);
    expect(uncompressedPubKey).to.have.lengthOf(130);
    expect(uncompressedPubKey.startsWith('04')).to.equal(true);
  });
});
