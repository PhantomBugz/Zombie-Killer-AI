Object.defineProperty(window, 'scrollTo', {
  configurable: true,
  value: () => undefined,
  writable: true,
})

afterEach(() => {
  document.documentElement.removeAttribute('data-theme')
})
