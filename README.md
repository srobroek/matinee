# Matinee

Matinee finds installed Firefox and Google Chrome executables for headed browser workflows.

## Install

```sh
cargo install matinee
```

## Usage

```sh
matinee doctor
```

Matinee searches standard application locations and `PATH`. When it finds at least one browser, it exits with status 0. If it finds none, it exits with status 1.

```sh
matinee --help
matinee --version
```

## License

The [Apache-2.0 license](LICENSE) governs Matinee.
