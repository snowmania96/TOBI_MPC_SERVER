<script lang="ts">
export const disabled = true;
</script>

{#if !disabled }
    <details open>
        <summary>
            <slot name="header">
                <strong>Signature generation</strong>
            </slot>
        </summary>

        <slot />
    </details>
{/if}
