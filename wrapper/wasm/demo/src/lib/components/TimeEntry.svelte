<script lang="ts">
export const time = 0;
export const label = "";
</script>

{#if time }
    <tr>
        <td><b>{label}</b></td>
        <td>{time}</td>
    </tr>
{/if}
