import { utils } from './index.ts';
import { SHA256 } from 'https://denopkg.com/chiefbiiko/sha256@v1.0.0/mod.ts';

utils.sha256 = async (message: Uint8Array): Promise<Uint8Array> => {
  return new SHA256().update(message).digest() as Uint8Array;
};

export * from './index.ts';
