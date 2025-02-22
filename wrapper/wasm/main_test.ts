import { assertEquals } from "https://deno.land/std@0.203.0/assert/mod.ts";
import {
  decodeHex,
  encodeHex,
} from "https://deno.land/std@0.203.0/encoding/hex.ts";
import {
  genInstanceId,
  init_dsg,
  KeygenSetup,
  KeygenSetupBuilder,
  Keyshare,
  verifyingKey,
  EdKeyshare,
  init_eddsa_dkg,
  join_eddsa_dkg_local,
  init_eddsa_dsg,
  init_ecdsa_migration,
  init_eddsa_migration,
  join_ecdsa_migration_local,
  join_eddsa_migration_local,
  LegacyKeyshare,
  Keyshares,
  init_migration,
  join_migration_local,
} from "./pkg/dkls_wasm.js";
import { init_dkg, join_dkg, join_dkg_local, join_dsg_local } from "./pkg/dkls_wasm.js";
// import { dsgSetupMessage, init_dsg, join_dsg } from "./pkg/dkls_wasm.js";
import { SetupMsg, start_dkg, start_dsg, start_ecdsa_migration, start_eddsa_dkg, start_eddsa_dsg, start_eddsa_migration, start_migration } from "./main.ts";
import { MsgRelayClient } from "./js/msg-relay.js";

import { test } from "./dkls_test.js";
import { SignSetupBuilder } from "./pkg/dkls_wasm.js";

const ENDPOINT = "ws://localhost:8080";

// const ENDPOINT = 'ws://msg-relay.process.sl-demo.internal:8080';
// const ENDPOINT = 'wss://sl-demo.fly.dev/v1/msg-relay';
import legacyShare1 from "../../legacy_keyshare_data/legacy_share1.json" with { type: "json" };

const SETUP_SK = decodeHex(
  "b2012ec2ce6c7b64d58caf81f024a2a7e39ad3cb446973ff3ab363e8593f845d",
);

const PartySk = [
  decodeHex("a9130afb437107b5fa4142e56467ddee72fa5abdbc7fcd1f2abbfa8b5b04ddc7"),
  decodeHex("e9fc53eb8734468630d5e317bf12e6f11fa654c4caf3f5921a2082475b24558e"),
  decodeHex("fcdc915b33c7503f9fe2ed07700ec02cee6c55f22773bc39f14869df005e8c4b"),
];

const PARTY_PK = [
  decodeHex("cfa1ff5424d14eb60614d7ddf65a32243d26ddf7000d10007853d7336395efe4"),
  decodeHex("8eb91174c3532ddf0a87eb1b17620282b36d9f5a535aeca22ab5d2f52b492d32"),
  decodeHex("2ac4da173f99dd2c48b6720ad3ceea62554fb8271b357fc8688b830510560aa0"),
];


enum MigAlgo {
  ECDSA = "ecdsa",
  EDDSA = "eddsa",
  BOTH = "both",
}

const TOBI_ECDSA_PUBLIC_KEY  = 70;
const TOBI_EDDSA_PUBLIC_KEY  = 71;

async function generatePartyKeys(baseUrl = 'http://localhost:8083', authToken = null) {
    const headers = {
        'Content-Type': 'application/json'
    };


    try {
        const response = await fetch(`${baseUrl}/v1/party-keys`, {
            method: 'POST',
            headers: headers
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data; // Will contain { party_vk: "..." }
    } catch (error) {
        console.error('Error generating party keys:', error);
        throw error;
    }
}
async function handleKeyMigration(baseUrl = 'http://localhost:8083') {
    try {
        const response = await fetch(`${baseUrl}/v1/key-migration`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                // Add any other required headers here
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.text(); // Since it returns a String
        console.log('Migration response:', data);
        return data;
    } catch (error) {
        console.error('Error during key migration:', error);
        throw error;
    }
}

test("load", async () => {
  console.log("gen-instance-id", genInstanceId());
});

const dkgOpts = (instance: Uint8Array, server_vk: string) => {
  return {
    instance,
    signingKey: SETUP_SK,
    threshold: 2,
    ttl: 30,
    keyshare: undefined ,
    parties: [
      {
        rank: 0,
        publicKey: PARTY_PK[0],
      },

      {
        rank: 0,
        publicKey: PARTY_PK[1],
      },

      {
        rank: 0,
        publicKey: decodeHex(server_vk),
      },
    ],
  };
};

const dsgOpts = (instance: Uint8Array, key_id: Uint8Array, server_vk: Uint8Array) => {
  return {
    instance,
    signingKey: SETUP_SK,
    key_id,
    ttl: 30,
    parties: [
      { publicKey: PARTY_PK[0] },
      { publicKey: server_vk },
    ],
  };
};

export function dkgSetupMessage(dkgOpts: any): SetupMsg {
  const builder = new KeygenSetupBuilder();

  for (const n of dkgOpts.parties) {
    builder.addParty(n.publicKey, 0);
  }

  const setup = builder.build(
    dkgOpts.instance,
    dkgOpts.ttl,
    dkgOpts.threshold,
    dkgOpts.signingKey,
  );

  return { setup_msg: encodeHex(setup), instance: encodeHex(dkgOpts.instance), 
    setup_vk: encodeHex(verifyingKey(SETUP_SK)), party_vk:encodeHex( dkgOpts.parties[2].publicKey )};

}

export function MigSetupMessage(dkgOpts: any, ecPubkey?: Uint8Array , edPubkey?: Uint8Array): SetupMsg {
  const builder = new KeygenSetupBuilder();

  for (const n of dkgOpts.parties) {
    builder.addParty(n.publicKey, 0);
  }

  if (ecPubkey) {
    builder.addTag(TOBI_ECDSA_PUBLIC_KEY, ecPubkey);
  } 

  if (edPubkey) {
    builder.addTag(TOBI_EDDSA_PUBLIC_KEY, edPubkey);
  }
  if (!ecPubkey || !edPubkey) {
    throw "Expected atleast one pubkey!"
  }

  const setup = builder.build(
    dkgOpts.instance,
    dkgOpts.ttl,
    dkgOpts.threshold,
    dkgOpts.signingKey,
  );

  return { setup_msg: encodeHex(setup), instance: encodeHex(dkgOpts.instance), 
    setup_vk: encodeHex(verifyingKey(SETUP_SK)), party_vk:encodeHex( dkgOpts.parties[2].publicKey )};

}

export function dsgSetupMessage(dsgOpts: any, message_data: Uint8Array, is_ecdsa: boolean): SetupMsg {
  const builder = new SignSetupBuilder(dsgOpts.key_id);

  for (const n of dsgOpts.parties) {
    builder.addParty(n.publicKey);
  }

  if (is_ecdsa) {
    builder.withHash(message_data);
  } else {
    builder.withRawMessage(message_data);
  }

  const setup = builder.build(
    dsgOpts.instance,
    dsgOpts.ttl,
    dsgOpts.signingKey,
  );

  return { setup_msg: encodeHex(setup), instance: encodeHex(dsgOpts.instance), 
    setup_vk: encodeHex(verifyingKey(SETUP_SK)), party_vk:encodeHex( dsgOpts.parties[1].publicKey )};
}


test("DKG 2 web + 1 cloud", async () => {
  await test_dkg();
});


test("DSG 2 web + 1 cloud", async () => {
  await test_dsg();
});

test("EdDSA DKG 2 web + 1 cloud", async () => {
  await test_eddsa_dkg();
});

test("EdDSA DSG 2 web + 1 cloud", async () => {
  const sign = await test_eddsa_dsg() as [Uint8Array, number];
  console.log("sign", encodeHex(sign[0]));
});
//
// test("ECDSA Key migration", async () => {
//   const data = decodeHex(legacyShare1.ecdsaKeyShare);
//   const keyshare = LegacyKeyshare.fromBytes(data);
//   await test_ecdsa_migration(keyshare);
// })
//
// test("Both Key migration", async () => {
//   const ec_share = LegacyKeyshare.fromBytes(decodeHex(legacyShare1.ecdsaKeyShare));
//   const ed_share = EdKeyshare.fromLegacyBytes(decodeHex(legacyShare1.eddsaKeyShare));
//   await test_both_migration(ec_share,ed_share);
// })

// test("Key migration EdDSA", async () => {
//   const data = decodeHex(legacyShare1.eddsaKeyShare);
//   const keyshare = EdKeyshare.fromLegacyBytes(data);
//   await test_eddsa_migration(keyshare);
// })



async function test_dkg(): Promise<[Keyshare, Keyshare, string]> {
  const abort = new AbortController();
  const ws = await MsgRelayClient.connect(
    ENDPOINT + "/v1/msg-relay",
    abort.signal,
  );

  try {
    const instance = genInstanceId();
    const res = await generatePartyKeys();
    const setup_msg = dkgSetupMessage(dkgOpts(instance, res.party_vk));

    ws.send(setup_msg.setup_msg);


    const p1 = init_dkg(
     decodeHex(setup_msg.instance),
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[0],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
    );

   const p2 = join_dkg_local(
      instance,
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[1],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
    );

    const resp = await Promise.all([
      p1,
      p2,
      start_dkg("http://localhost:8083", setup_msg),
    ]);

    
    return [resp[0], resp[1], resp[2].publicKey];
  } catch (error) {
    console.log("ERROR", error);
    throw error;
  } finally {
    await ws.close();
  }
}

async function test_dsg() {
  const shares = await test_dkg();
  const share1 = shares[0]!;
  const share2 = shares[1]!;
  const publicKey= shares[2]

  const abort = new AbortController();
  const ws = await MsgRelayClient.connect(
    ENDPOINT + "/v1/msg-relay",
    abort.signal,
  );

  try {
    const instance = genInstanceId();
    const res = await generatePartyKeys();
    const setup_msg = dsgSetupMessage(dsgOpts(instance,share1.keyId(), 
      decodeHex(res.party_vk)), decodeHex("cfa1ff5424d14eb60614d7ddf65a32243d26ddf7000d10007853d7336395efe4"), true);

    ws.send(setup_msg.setup_msg);


    const p1 = init_dsg(
     decodeHex(setup_msg.instance),
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[0],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
      share1,
    );


    const resp = await Promise.all([
      p1,
      start_dsg("http://localhost:8083", setup_msg),
    ]);

    const share = resp[0];
    
    return resp;
  } catch (error) {
    console.log("ERROR", error);
  } finally {
    await ws.close();
  }
}


async function test_eddsa_dkg(): Promise<[EdKeyshare, EdKeyshare, string]> {
  const abort = new AbortController();
  const ws = await MsgRelayClient.connect(
    ENDPOINT + "/v1/msg-relay",
    abort.signal,
  );

  try {
    const instance = genInstanceId();
    const res = await generatePartyKeys();
    const setup_msg = dkgSetupMessage(dkgOpts(instance, res.party_vk));

    ws.send(setup_msg.setup_msg);


    const p1 = init_eddsa_dkg(
     decodeHex(setup_msg.instance),
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[0],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
    );

   const p2 = join_eddsa_dkg_local(
      instance,
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[1],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
    );

    const resp = await Promise.all([
      p1,
      p2,
      start_eddsa_dkg("http://localhost:8083", setup_msg),
    ]);

    
    return [resp[0], resp[1], resp[2].publicKey];
  } catch (error) {
    console.log("ERROR", error);
    throw error;
  } finally {
    
    await ws.close();
  }
}

async function test_eddsa_dsg() {
  const shares = await test_eddsa_dkg();
  const share1 = shares[0]!;
  console.log("Public key", encodeHex(share1.publicKey()));
  const publicKey= shares[2]

  const abort = new AbortController();
  const ws = await MsgRelayClient.connect(
    ENDPOINT + "/v1/msg-relay",
    abort.signal,
  );

  try {
    const instance = genInstanceId();
    const res = await generatePartyKeys();
    const enc = new TextEncoder();
    const message_data = enc.encode("Hello World!");
    const setup_msg = dsgSetupMessage(dsgOpts(instance,share1.keyId(), 
      decodeHex(res.party_vk)), message_data, false);

    ws.send(setup_msg.setup_msg);


    const p1 = init_eddsa_dsg(
     decodeHex(setup_msg.instance),
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[0],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
      share1,
    );


    const resp = await Promise.all([
      p1,
      start_eddsa_dsg("http://localhost:8083", setup_msg),
    ]);

    return resp;
  } catch (error) {
    console.log("ERROR", error);
  } finally {
    await ws.close();
  }
}

async function test_both_migration(keyshare1: LegacyKeyshare, keyshare2: EdKeyshare): Promise<[Keyshares, Keyshares, string]> {
  const abort = new AbortController();
  const ws = await MsgRelayClient.connect(
    ENDPOINT + "/v1/msg-relay",
    abort.signal,
  );

  try {
    const instance = genInstanceId();
    const res = await generatePartyKeys();
    const ecPubkey = keyshare1.publicKey();
    const edPubkey = keyshare2.publicKey();
    
    const setup_msg = MigSetupMessage(dkgOpts(instance, res.party_vk), ecPubkey, edPubkey );

    ws.send(setup_msg.setup_msg);


    const p1 = init_migration(
      decodeHex(setup_msg.instance),
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[0],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
      genInstanceId(),
      keyshare1,
      keyshare2,
    );

   const p2 = join_migration_local(
      instance,
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[1],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
      genInstanceId(),
    );

    const resp = await Promise.all([
      p1,
      p2,
      start_migration("http://localhost:8083", setup_msg),
    ]);

    
    return [resp[0], resp[1], resp[2].publicKey];
  } catch (error) {
    console.log("ERROR", error);
    throw error;
  } finally {
    await ws.close();
  }
}


async function test_ecdsa_migration(keyshare1: LegacyKeyshare): Promise<[Keyshare, Keyshare, string]> {
  const abort = new AbortController();
  const ws = await MsgRelayClient.connect(
    ENDPOINT + "/v1/msg-relay",
    abort.signal,
  );

  try {
    const instance = genInstanceId();
    const res = await generatePartyKeys();
    const publicKey = keyshare1.publicKey();
    const setup_msg = MigSetupMessage(dkgOpts(instance, res.party_vk), publicKey, undefined);

    ws.send(setup_msg.setup_msg);


    const p1 = init_ecdsa_migration(
      decodeHex(setup_msg.instance),
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[0],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
      keyshare1,
    );

   const p2 = join_ecdsa_migration_local(
      instance,
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[1],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
    );

    const resp = await Promise.all([
      p1,
      p2,
      start_ecdsa_migration("http://localhost:8083", setup_msg),
    ]);

    
    return [resp[0], resp[1], resp[2].publicKey];
  } catch (error) {
    console.log("ERROR", error);
    throw error;
  } finally {
    await ws.close();
  }
}

async function test_eddsa_migration(keyshare1: EdKeyshare): Promise<[EdKeyshare, EdKeyshare, string]> {
  const abort = new AbortController();
  const ws = await MsgRelayClient.connect(
    ENDPOINT + "/v1/msg-relay",
    abort.signal,
  );

  try {
    const instance = genInstanceId();
    const res = await generatePartyKeys();
    const publicKey = keyshare1.publicKey();
    const setup_msg = MigSetupMessage(dkgOpts(instance, res.party_vk), undefined,publicKey);

    ws.send(setup_msg.setup_msg);


    const p1 = init_eddsa_migration(
      decodeHex(setup_msg.instance),
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[0],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
      keyshare1,
    );

   const p2 = join_eddsa_migration_local(
      instance,
      decodeHex(setup_msg.setup_msg),
      verifyingKey(SETUP_SK),
      PartySk[1],
      ENDPOINT + "/v1/msg-relay",
      genInstanceId(),
    );

    const resp = await Promise.all([
      p1,
      p2,
      start_eddsa_migration("http://localhost:8083", setup_msg),
    ]);

    
    return [resp[0], resp[1], resp[2].publicKey];
  } catch (error) {
    console.log("ERROR", error);
    throw error;
  } finally {
    await ws.close();
  }
}
