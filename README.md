![Banner](banner.png)

# dso-log-scrubber
Removes or obfuscates sensitive information from log files to prevent data leaks. Supports customizable patterns for different log formats. - Focused on Tools for sanitizing and obfuscating sensitive data within text files and structured data formats

There are no built in patterns. The operator supplies every pattern on the command line.

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-log-scrubber`

## Usage
`./dso-log-scrubber [params]`

`python main.py input.log output.log --patterns PATTERN [PATTERN ...] [--replace_with TEXT] [--inplace] [--encoding ENCODING]`

## Parameters
- `-h`: Show help message and exit
- `--patterns`: List of regular expression patterns to find sensitive data. Every pattern is validated and compiled before any line is processed. An invalid pattern ends the run at exit 1 and no output file is written.
- `--replace_with`: Text to replace sensitive data with. Use "fake_name", "fake_email", "fake_address", "fake_phone_number", or "fake_credit_card_number" for fake data generation. Defaults to deletion. A fake option needs the faker package to be importable. If faker is not installed, a run that asks for a fake option ends at exit 1 with a plain error line and writes no output. Runs that do not ask for a fake option do not need faker.
- `--inplace`: Overwrite the input file with the sanitized output. This flag is the consent for a same path run: if the resolved output path is the input file, through the same string, a ./ alias, or a symlink, the run is refused at exit 1 unless `--inplace` was given. With `--inplace`, that same path run proceeds.
- `--encoding`: Specify the encoding of the input file. If not provided, encoding will be auto-detected.

## Exit codes
- `0`: The run scrubbed at least one match and wrote its output. The run logs how many substitutions were made and how many lines changed.
- `1`: The run failed or scrubbed nothing. This covers a missing or unreadable input file, an invalid pattern, a fake option requested while faker is not installed, a same path output without `--inplace`, and any other error in the scrub. A run that matches nothing prints a plain "Nothing was scrubbed" line, ends at exit 1, and writes no output.

## License
Copyright (c) ShadowStrikeHQ
