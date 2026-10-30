import babelParser from '@babel/eslint-parser'
import js from '@eslint/js'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import globals from 'globals'

const readonlyGlobals = (...sets) =>
  Object.fromEntries(sets.flatMap((set) => Object.keys(set)).map((name) => [name, 'readonly']))

const typeScriptLanguageOptions = (environmentGlobals) => ({
  ecmaVersion: 'latest',
  globals: readonlyGlobals(environmentGlobals),
  parser: babelParser,
  parserOptions: {
    requireConfigFile: false,
    sourceType: 'module',
    babelOptions: {
      plugins: ['@babel/plugin-syntax-jsx', ['@babel/plugin-syntax-typescript', { isTSX: true }]],
    },
  },
})

const reactPlugins = {
  'react-hooks': reactHooks,
  'react-refresh': reactRefresh,
}

const reactRules = {
  ...reactHooks.configs.recommended.rules,
  ...reactRefresh.configs.vite.rules,
  'no-undef': 'off',
  'no-unused-vars': 'off',
}

const forbiddenProductionGlobals = Object.keys({ ...globals.node, ...globals.vitest }).filter(
  (name) => !(name in globals.browser),
)

export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'src-tauri/target/**', 'src-tauri/resources/engine/**'],
  },
  js.configs.recommended,
  {
    files: ['public/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      globals: readonlyGlobals(globals.browser),
      sourceType: 'module',
    },
  },
  {
    files: ['eslint.config.js', 'scripts/**/*.{js,mjs}'],
    languageOptions: {
      ecmaVersion: 'latest',
      globals: readonlyGlobals(globals.node),
      sourceType: 'module',
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/test/**'],
    languageOptions: typeScriptLanguageOptions(globals.browser),
    plugins: reactPlugins,
    rules: {
      ...reactRules,
      'no-restricted-globals': ['error', ...forbiddenProductionGlobals],
    },
  },
  {
    files: ['src/test/**/*.{ts,tsx}'],
    languageOptions: typeScriptLanguageOptions({
      ...globals.browser,
      ...globals.node,
      ...globals.vitest,
    }),
    plugins: reactPlugins,
    rules: reactRules,
  },
  {
    files: ['vite.config.ts'],
    languageOptions: typeScriptLanguageOptions(globals.node),
    rules: {
      'no-undef': 'off',
      'no-unused-vars': 'off',
    },
  },
]
