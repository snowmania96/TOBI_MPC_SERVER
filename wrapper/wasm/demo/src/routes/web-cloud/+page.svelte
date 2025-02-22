<script lang="ts">
  import TimeMetrics from "$lib/components/TimeMetrics.svelte";
  import SummaryTimes from "$lib/components/SummaryTimes.svelte";
  import SubSection from "$lib/components/SubSection.svelte";
  import SelectPublicKey from "$lib/components/SelectPublicKey.svelte";
  import { clusterConfig, wsUrl } from "$lib/config";
  import type { ClusterDef } from "$lib/config";
  import { decodeBase64, encodeBase64 } from "$lib/base64";
  import { encodeHex } from "$lib/hex";
  import { keyshares } from "$lib/stores";

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
    randomSeed,
  } from "$lib/nodes";

  import {
    init_dkg,
    init_dsg,
    init_pre,
    init_finish,
    msg_relay_connect,
    createAbortMessage,
    type Keyshare,
  } from "dkls-wasm";

  let busy = false;

  let threshold = 2;
  let partiesNumber = 3;

  let keygenWebStats: KeygenResponse[] = [];
  let keygenWebTimes = {};

  let signNum = 1;
  let signHashFn: HashFn = "SHA256";
  let signMessage = "Something to sign";
  const preSignId: Uint8Array | null = null;

  const signStats: any | null = null;
  const signTimes = {};

  const finSignStats: SignResponse[] = [];
  const finSignTimes = {};

  let signInitName = "";
  let signResult = "";

  $: validPartiesNum =
    +partiesNumber && partiesNumber >= 2 && partiesNumber <= 3;
  $: validThreshold = +threshold && threshold > 1 && threshold <= partiesNumber;

  let selectShare = false;
  let selectedShare: Keyshare | null = null;

  const withBusy = async (body: (defs: ClusterDef) => Promise<void>) => {
    busy = true;
    const loadedConfig = await clusterConfig();

    try {
      await body(loadedConfig);
    } finally {
      busy = false;
    }
  };

  const resetSign = (init = "") => {
    signResult = "";
    preSignId = null;
    signInitName = init;
  };

  const handleGenKeysWeb = async () => {
    const startTime = Date.now();

    resetSign();

    await withBusy(async (loadedConfig) => {
      const msgRelayUrl = wsUrl(loadedConfig.setup.relay);
      const { setup, instance } = createKeygenSetup(
        loadedConfig,
        partiesNumber,
        threshold,
      );

      const web_party = init_dkg(
        instance,
        setup,
        loadedConfig.setup.publicKey,
        loadedConfig.nodes[0].secretKey,
        msgRelayUrl,
        randomSeed(),
      );

      const [share, ...clouds] = await Promise.all([
        web_party,
        ...loadedConfig.nodes
          .slice(1, partiesNumber)
          .map((n) => startDkg(n.endpoint, instance, setup)),
      ]);

      const genEnd = Date.now();

      console.log("pk", encodeHex(share.publicKey()));
      console.log("key_id", encodeBase64(share.keyId()));

      keyshares.update((shares) => [...shares, share]);

      if (selectedShare === null) {
        selectedShare = share;
      }

      keygenWebStats = clouds;

      keygenWebTimes = {
        totalTime: genEnd - startTime,
      };
    });
  };

  const handleSignGen = async (isPre: boolean) => {
    if (selectedShare === null) {
      return;
    }

    const startTime = Date.now();

    const selectedKeyId = selectedShare.keyId();

    resetSign(isPre ? "PreSignature" : "FullSignature");

    await withBusy(async (loadedConfig) => {
      const { setup, instance } = await createSignSetup(
        loadedConfig,
        threshold,
        selectedKeyId,
        isPre ? undefined : messageHash(signHashFn, signMessage),
      );

      const msgRelayUrl = wsUrl(loadedConfig.setup.relay);

      const web_party = (isPre ? init_pre : init_dsg)(
        instance,
        setup,
        loadedConfig.setup.publicKey,
        loadedConfig.nodes[0].secretKey,
        msgRelayUrl,
        randomSeed(),
        selectedShare,
      );

      const resp = await Promise.all([
        web_party,
        ...loadedConfig.nodes
          .slice(1, threshold)
          .map((n) =>
            (isPre ? startPreSign : startDsg)(n.endpoint, instance, setup),
          ),
      ]);

      signStats = resp.slice(1);

      const genEnd = Date.now();

      signTimes = {
        totalTime: genEnd - startTime,
      };

      if (isPre) {
        preSignId = resp[0];
      } else {
        signResult = encodeHex(resp[0]);
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
        preSignId,
        messageHash(signHashFn, signMessage),
      );

      const msgRelayUrl = wsUrl(loadedConfig.setup.relay);

      const web_party = init_finish(
        instance,
        setup,
        loadedConfig.setup.publicKey,
        loadedConfig.nodes[0].secretKey,
        msgRelayUrl,
      );

      const resp = await Promise.all([
        web_party,
        ...loadedConfig.nodes
          .slice(1, threshold)
          .map((n) => startFinSign(n.endpoint, instance, setup)),
      ]);

      const genEnd = Date.now();

      finSignStats = resp.slice(1);
      finSignTimes = {
        totalTime: genEnd - startTime,
      };

      signResult = encodeHex(resp[0]);
    });
  };

  const doSelectShare = (share: Keyshare) => {
    selectShare = false;
    selectedShare = share;
    console.log("current share", share);
  };

  const isSelectedShare = (share: Keyshare) => {
    return share === selectedShare;
  };

  const sharePk = (share: Keyshare | null) =>
    share ? encodeHex(share.publicKey()) : "";

  const handlePreSignGen = async () => {};
</script>

<p>
  An MPC network whereby one node is running as a web node and the others are
  cloud nodes. In this scenario, web node initialize execution a protocol and
  also is a part of the MPC network.
</p>

<details open>
  <summary>
    <strong> First step: generation a distributed key. </strong>
  </summary>

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
      on:click={handleGenKeysWeb}
      disabled={!validPartiesNum || !validThreshold}
    >
      Generate key
    </button>
  </div>

  <SummaryTimes {...keygenWebTimes} />

  <TimeMetrics stats={keygenWebStats} offset={1}>
    <p>Participant number one is this web page.</p>
  </TimeMetrics>
</details>

<SubSection disabled={$keyshares.length == 0}>
  <p>
    Prepare a setup message, send it to other participants and start execution
    of DSG on this machine.
  </p>

  <details role="list" bind:open={selectShare}>
    <summary aria-haspopup="listbox">{sharePk(selectedShare)}</summary>
    <ul role="listbox">
      {#each $keyshares as share}
        <li>
          <label for="pk">
            <span
              role="button"
              tabindex="-1"
              on:click={() => doSelectShare(share)}
              on:keypress={() => null}
            >
              <input
                type="radio"
                name="pk"
                value={sharePk(share)}
                checked={isSelectedShare(share)}
              />
              {sharePk(share)}
            </span>
          </label>
        </li>
      {/each}
    </ul>
  </details>

  <input
    type="text"
    placeholder="Enter messaege to sign"
    bind:value={signMessage}
  />

  <div class="grid">
    <button aria-busy={busy} on:click={() => handleSignGen(false)}>
      Full
    </button>

    <button aria-busy={busy} on:click={() => handleSignGen(true)}>
      PreSign
    </button>

    <button
      aria-busy={busy}
      disabled={preSignId === null}
      on:click={handleFinish}
    >
      Finish
    </button>
  </div>

  {#if signInitName}
    <h6>Stage: {signInitName}</h6>
  {/if}

  <SummaryTimes {...signTimes} />
  <TimeMetrics stats={signStats} offset={1} />

  {#if preSignId !== null && finSignStats.length > 0}
    <h6>Stage: Finish signature</h6>
    <SummaryTimes {...finSignTimes} />
    <TimeMetrics stats={finSignStats} offset={1} />
  {/if}

  {#if signResult !== ""}
    <h6>hex((r,s), recid)</h6>
    <strong>Sign: {signResult}</strong>
  {/if}
</SubSection>
