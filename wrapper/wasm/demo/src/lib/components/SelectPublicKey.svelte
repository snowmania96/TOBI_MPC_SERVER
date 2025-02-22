<script lang="ts">
import { cloudPublicKeys } from "$lib/stores";
export const doSelectKey = (key: string) => undefined;
export const selectedKeyId = "";
const keyInfo = (key: string) => {
	const info = $cloudPublicKeys[key];
	return `${info.publicKey} | N: ${info?.n}, T ${info?.t}`;
};
let selectPk = false;
const handleClick = (key) => () => {
	selectPk = false;
	doSelectKey(key);
};
</script>

<details role="list" bind:open={selectPk}>
  <summary aria-haspopup="listbox">
    {keyInfo(selectedKeyId)}
  </summary>
  <ul role="listbox">
    {#each Object.entries($cloudPublicKeys) as [key, info]}
      <li>
        <label for={info.publicKey}>
          <span
            role="button"
            tabindex="-1"
            on:click={handleClick(key)}
            on:keypress={() => null}
          >
            <input
              type="radio"
              name="pk"
              value={key}
              id={info.publicKey}
              checked={key == selectedKeyId}
            />
            {info.publicKey}
          </span>
        </label>
      </li>
    {/each}
  </ul>
</details>
