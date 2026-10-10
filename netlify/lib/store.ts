// A tiny key-value layer over Netlify Blobs, with an in-memory fallback so the
// app runs under `netlify dev` and the tests run under plain node. Each logical
// collection is a namespace; values are JSON.

import { getStore, type Store } from "@netlify/blobs";

interface KV {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<void>;
  list(): Promise<string[]>;
}

class BlobKV implements KV {
  constructor(private store: Store) {}
  async get<T>(key: string): Promise<T | null> {
    return (await this.store.get(key, { type: "json" })) as T | null;
  }
  async set<T>(key: string, value: T): Promise<void> {
    await this.store.setJSON(key, value as unknown as object);
  }
  async delete(key: string): Promise<void> {
    await this.store.delete(key);
  }
  async list(): Promise<string[]> {
    const { blobs } = await this.store.list();
    return blobs.map((b) => b.key);
  }
}

class MemoryKV implements KV {
  private m = new Map<string, string>();
  async get<T>(key: string): Promise<T | null> {
    const v = this.m.get(key);
    return v === undefined ? null : (JSON.parse(v) as T);
  }
  async set<T>(key: string, value: T): Promise<void> {
    this.m.set(key, JSON.stringify(value));
  }
  async delete(key: string): Promise<void> {
    this.m.delete(key);
  }
  async list(): Promise<string[]> {
    return [...this.m.keys()];
  }
}

const memo = new Map<string, KV>();

export function kv(namespace: string): KV {
  const existing = memo.get(namespace);
  if (existing) return existing;
  let store: KV;
  try {
    store = new BlobKV(getStore({ name: `tessera-${namespace}`, consistency: "strong" }));
  } catch {
    // No Blobs context (plain node / tests) — fall back to process memory.
    store = new MemoryKV();
  }
  memo.set(namespace, store);
  return store;
}
