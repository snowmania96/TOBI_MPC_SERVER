<script lang="ts">
  import TimeMetrics from "$lib/components/TimeMetrics.svelte";
  import SummaryTimes from "$lib/components/SummaryTimes.svelte";
  import SubSection from "$lib/components/SubSection.svelte";
  import SelectPublicKey from "$lib/components/SelectPublicKey.svelte";
  import { clusterConfig, wsUrl } from "$lib/config";
  import { type ClusterDef, SignAlgo } from "$lib/config";
  import { decodeBase64, encodeBase64 } from "$lib/base64";
  import { encodeHex, decodeHex } from "$lib/hex";
  import { cloudPublicKeys } from "$lib/stores";
  import { msg_relay_connect } from "dkls-wasm";

  import {
    createKeygenSetup,
    createSignSetup,
    type HashFn,
    messageHash,
    createFinishSetup,
    startDkg,
    type KeygenResponse,
    startDsg,
    type SignResponse,
    startPreSign,
    startFinSign,
  } from "$lib/nodes";

  let busy = false;

  let threshold = 2;
  let partiesNumber = 3;

  let keygenStats: KeygenResponse[] = [];
  let keygenTimes = {};

  let signNum = 1;
  const signHashFn: HashFn = "KECCAK256";
  let signMessage = "Something to sign";

  let signStats: SignResponse[] = [];
  let signTimes = {};

  let preSignStats: SignResponse[] = [];
  let preSignTimes = {};

  let finSignStats: SignResponse[] = [];
  let finSignTimes = {};

  let preSignId = "";

  let selectedKeyId = "";

  $: validPartiesNum =
    +partiesNumber && partiesNumber >= 2 && partiesNumber <= 3;
  $: validThreshold = +threshold && threshold > 1 && threshold <= partiesNumber;

  const withBusy = async (body: (defs: ClusterDef) => Promise<void>) => {
    busy = true;
    const loadedConfig = await clusterConfig();

    try {
      await body(loadedConfig);
    } finally {
      busy = false;
    }
  };

  const handleGenKeys = async (signAlgo: SignAlgo) => {
    const startTime = Date.now();

    await withBusy(async (loadedConfig) => {
      const { setup, instance } = createKeygenSetup(
        signAlgo,
        loadedConfig,
        partiesNumber,
        threshold,
      );

      const resp: KeygenResponse[] = await Promise.all(
        loadedConfig.nodes
          .slice(0, partiesNumber)
          .map((n) => startDkg(signAlgo, n.endpoint, instance, setup)),
      );

      const genEnd = Date.now();

      keygenStats = resp;
      keygenTimes = {
        totalTime: genEnd - startTime,
      };

      console.log("resp[0]", resp[0]);
      console.log(Object.keys(cloudPublicKeys).length);

      cloudPublicKeys.update((keys) => {
        return {
          ...keys,
          [resp[0].key_id]: {
            publicKey: resp[0].public_key,
            n: partiesNumber,
            t: threshold,
          },
        };
      });

      if (selectedKeyId === "") {
        selectedKeyId = resp[0].key_id;
      }
    });
  };

  const handleSignGen = async (signAlgo: SignAlgo) => {
    const startTime = Date.now();

    await withBusy(async (loadedConfig) => {
      const { setup, instance } = createSignSetup(
        signAlgo,
        loadedConfig,
        threshold,
        decodeBase64(selectedKeyId),
        messageHash(signHashFn, signMessage),
      );

      const resp: SignResponse[] = await Promise.all(
        loadedConfig.nodes
          .slice(0, threshold)
          .map((n) => startDsg(signAlgo, n.endpoint, instance, setup)),
      );

      const genEnd = Date.now();

      signStats = resp;
      signTimes = {
        totalTime: genEnd - startTime,
      };

      console.log("resp", resp);
    });
  };

  const handlePreSignGen = async () => {
    const startTime = Date.now();

    await withBusy(async (loadedConfig) => {
      const { setup, instance } = createSignSetup(
        loadedConfig,
        threshold,
        decodeHex(selectedKeyId),
      );

      const resp = await Promise.all(
        loadedConfig.nodes
          .slice(0, threshold)
          .map((n) => startPreSign(n.endpoint, instance, setup)),
      );

      const genEnd = Date.now();

      preSignStats = resp;
      preSignTimes = {
        totalTime: genEnd - startTime,
      };

      console.log("resp", resp[0].preSignId);

      if (resp[0].preSignId) {
        preSignId = resp[0].preSignId;
      }
    });
  };

  const handleFinish = async () => {
    const startTime = Date.now();

    await withBusy(async (loadedConfig) => {
      console.log("fin", preSignId);
      const { setup, instance } = createFinishSetup(
        loadedConfig,
        threshold,
        decodeHex(preSignId),
        messageHash(signHashFn, signMessage),
      );

      // forget about preSignId;
      // preSignId = "";

      const resp = await Promise.all(
        loadedConfig.nodes
          .slice(0, threshold)
          .map((n) => startFinSign(n.endpoint, instance, setup)),
      );

      const genEnd = Date.now();

      finSignStats = resp;
      finSignTimes = {
        totalTime: genEnd - startTime,
      };

      console.log("resp", resp[0]);
    });
  };
</script>

<details open>
  <summary>
    <strong>Key generation with "all cloud nodes" network</strong>
  </summary>

  <p>
    The web application authorizes cloud nodes to generate a distributed key in
    this variant. All computations performed by cloud nodes and resulting shares
    of a generated key are stored in the cloud.
  </p>

  <div class="grid">
    <input
      type="text"
      name="threshold"
      placeholder="Threshold"
      aria-invalid={validThreshold ? "false" : "true"}
      bind:value={threshold}
    />
    <input
      type="text"
      name="participants"
      placeholder="Number of parties"
      aria-invalid={!validPartiesNum}
      bind:value={partiesNumber}
    />
    <button
      aria-busy={busy}
      on:click={() => handleGenKeys(SignAlgo.Ecdsa)}
      disabled={!validPartiesNum || !validThreshold}
    >
      Generate key (ECDSA)
    </button>
    <button
      aria-busy={busy}
      on:click={() => handleGenKeys(SignAlgo.Taproot)}
      disabled={!validPartiesNum || !validThreshold}
    >
      Generate key (Bitcoin Taproot)
    </button>
    <button
      aria-busy={busy}
      on:click={() => handleGenKeys(SignAlgo.EdDSA)}
      disabled={!validPartiesNum || !validThreshold}
    >
      Generate key (EdDSA)
    </button>
  </div>

  <SummaryTimes {...keygenTimes} />
  <TimeMetrics stats={keygenStats} showLegend={true} />
</details>

<SubSection disabled={Object.keys($cloudPublicKeys).length === 0}>
  <p>
    Prepare a SetupMessage, send it to all participants and wait for resulting
    signature.
  </p>

  <p>
    We could generate more than one signature in a row to get more realistic
    metrics of execution time. <b> TODO </b>
  </p>

  <SelectPublicKey
    {selectedKeyId}
    doSelectKey={(key) => {
      selectedKeyId = key;
    }}
  />

  <div class="grid">
    <input
      type="text"
      placeholder="Enter message to sign"
      bind:value={signMessage}
    />

    <input type="number" bind:value={signNum} placeholder="N" />

    <button aria-busy={busy} on:click={() => handleSignGen(SignAlgo.Ecdsa)}>
      Generate signature (ECDSA)
    </button>

    <button aria-busy={busy} on:click={() => handleSignGen(SignAlgo.Taproot)}>
      Generate signature (Bitcoin Taproot)
    </button>
    <button aria-busy={busy} on:click={() => handleSignGen(SignAlgo.EdDSA)}>
      Generate signature (EdDSA)
    </button>
  </div>

  <SummaryTimes {...signTimes} />
  <TimeMetrics stats={signStats} />
</SubSection>

<SubSection disabled={Object.keys($cloudPublicKeys).length == 0}>
  <strong slot="header"> Generate PreSignature </strong>

  <p>
    Prepare a PreSignature setup message, send it all participants and receive
    pre-siginature ID.
  </p>

  <p>
    PreSignature ID should be used to generate ECDSA singnature by fast, single
    round protocol.
  </p>

  <SelectPublicKey
    {selectedKeyId}
    doSelectKey={(key) => {
      selectedKeyId = key;
    }}
  />

  <button aria-busy={busy} on:click={handlePreSignGen}>
    Generate PreSignature
  </button>

  <SummaryTimes {...preSignTimes} />
  <TimeMetrics stats={preSignStats} />
</SubSection>

<SubSection disabled={preSignId === ""}>
  <strong slot="header"> Finish PreSignature </strong>

  <div class="grid">
    <input
      type="text"
      placeholder="Enter messaege to sign"
      bind:value={signMessage}
    />

    <button aria-busy={busy} on:click={handleFinish}>
      Finish PreSignature
    </button>
  </div>

  <SummaryTimes {...finSignTimes} />
  <TimeMetrics stats={finSignStats} />
</SubSection>
