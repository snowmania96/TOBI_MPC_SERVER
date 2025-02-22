import * as base64 from "https://deno.land/x/base64/mod.ts";

import "./load-dkls.ts";

const start = async (
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> => {
  const resp = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(setup_msg),
  });

  if (resp.status != 200) {
    console.log("resp status", endpoint, resp.status, await resp.text());
    throw new Error("status " + resp.status);
  }

  return await resp.json();
};

export interface SetupMsg {
  instance: string,
  setup_msg: string,
  setup_vk: string,
  party_vk: string,
}

export async function start_dkg(
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> {
  const resp = await start(endpoint + "/v1/keygen",setup_msg);

  return resp;
}

export async function start_ecdsa_migration(
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> {
  const resp = await start(endpoint + "/v1/ecdsa-key-migration",setup_msg);
  return resp;
}

export async function start_migration(
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> {
  const resp = await start(endpoint + "/v1/key-migration",setup_msg);
  return resp;
}

export async function start_eddsa_migration(
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> {
  const resp = await start(endpoint + "/v1/eddsa-key-migration",setup_msg);
  return resp;
}

export async function start_eddsa_dkg(
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> {
  const resp = await start(endpoint + "/v1/eddsa-keygen",setup_msg);

  return resp;
}

export async function start_dsg(
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> {
  const resp = await start(endpoint + "/v1/signgen", setup_msg);

  return resp;
}

export async function start_eddsa_dsg(
  endpoint: string,
  setup_msg: SetupMsg,
): Promise<any> {
  const resp = await start(endpoint + "/v1/eddsa-signgen", setup_msg);

  return resp;
}
