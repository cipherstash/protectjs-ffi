// This module is the CJS entry point for the library.

// The Rust addon.
import * as addon from './load.cjs';

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
  function createEqlPayload(value: string, table: string, column: string, callback: callback): string;
}

type callback = (result: string) => void;


export interface EqlPayload { // TODO: Make generic
  value: string,
  table: string,
  column: string
}

export function createEqlPayload({ value, table, column}: EqlPayload): Promise<string> {
  return new Promise((resolve, reject) => {
    addon.createEqlPayload(value, table, column, (result: string) => resolve(result));
  })
}
