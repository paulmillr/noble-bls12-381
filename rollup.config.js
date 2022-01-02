import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'lib/index.js',
  output: {
    file: 'build/noble-bls12-381.js',
    format: 'umd',
    name: 'nobleBls12381',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve(), commonjs()],
};
