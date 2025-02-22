<script lang="ts">
import TimeEntry from "./TimeEntry.svelte";

export const totalTime = 0;
export const setupGenTime = 0;
export const relayConnTime = 0;

const show = totalTime > 0 || setupGenTime > 0 || relayConnTime > 0;
</script>

{#if show}
<table>
    <thead>
        <tr>
            <th>Metric</th>
            <th>Time, ms</th>
        </tr>
    </thead>

    <tbody>
        <TimeEntry time={setupGenTime} label="setupGenTime" />
        <TimeEntry time={relayConnTime} label="relayConnTime" />
        <TimeEntry time={totalTime} label="totalTime" />
    </tbody>
</table>
{/if}
