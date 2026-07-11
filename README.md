# Garbled Circuits

Source for [garbled.foundation](https://garbled.foundation) — a plain-spoken,
working explanation of Yao's garbled circuits (Andrew Yao, FOCS '86) and secure
two-party computation, aimed at engineers rather than cryptographers. Second
site in the same small network as [Pedersen
Commitments](https://pedersen.foundation), reusing its design system and Astro
setup.

Every historical claim is sourced (see `/history` and `/further-reading`), and
every interactive demo computes real values client-side — nothing is mocked. See
`/about` for what this site is and how to contribute.

## Stack

- [Astro](https://astro.build) (static output, island architecture)
- Content in MDX (`src/pages/*.mdx`)
- [KaTeX](https://katex.org) for math, via `remark-math`/`rehype-katex`
- [Shiki](https://shiki.style) for code highlighting (Astro's default)
- The garbled-gate demo uses only the browser's built-in Web Crypto API
  (`crypto.subtle.digest('SHA-256', ...)`, `crypto.getRandomValues`) — no
  external crypto library needed, unlike the Pedersen Commitments site's EC demos — see
  `src/lib/`

## Development

```sh
npm install
npm run dev      # http://localhost:4321
npm run build    # static output to ./dist
npm run astro check
```

## Contributing

Corrections and additions are welcome — open an issue or a pull request. See
`/about` on the live site for more.

## License

Code is [MIT](LICENSE). Written content is [CC-BY 4.0](LICENSE-CONTENT.md).
