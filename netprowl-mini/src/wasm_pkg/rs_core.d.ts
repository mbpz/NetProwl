/* tslint:disable */
/* eslint-disable */

export function discover_mdns(service_types: string[], timeout_ms: bigint): string;

export function discover_ssdp(timeout_ms: bigint): string;

export function expand_subnet(subnet: string): string;

export function grab_banner(ip: string, port: number, timeout_ms: bigint): string;

export function guess_gateway(local_ip: string): string;

export function guess_service(port: number): string;

export function infer_subnet(local_ip: string): string | undefined;

export function init(): void;

export function is_private_ip(ip: string): boolean;

export function lookup_vendor(mac: string): string | undefined;

export function probe_tcp_ports(ip: string, ports: Uint16Array, timeout_ms: bigint): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly discover_mdns: (a: number, b: number, c: bigint) => [number, number];
    readonly discover_ssdp: (a: bigint) => [number, number];
    readonly expand_subnet: (a: number, b: number) => [number, number];
    readonly grab_banner: (a: number, b: number, c: number, d: bigint) => [number, number];
    readonly guess_gateway: (a: number, b: number) => [number, number];
    readonly guess_service: (a: number) => [number, number];
    readonly infer_subnet: (a: number, b: number) => [number, number];
    readonly init: () => void;
    readonly is_private_ip: (a: number, b: number) => number;
    readonly lookup_vendor: (a: number, b: number) => [number, number];
    readonly probe_tcp_ports: (a: number, b: number, c: number, d: number, e: bigint) => [number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
