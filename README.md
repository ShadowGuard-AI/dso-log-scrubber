# dso-log-scrubber
Removes or obfuscates sensitive information from log files to prevent data leaks. Supports customizable patterns for different log formats. - Focused on Tools for sanitizing and obfuscating sensitive data within text files and structured data formats

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-log-scrubber`

## Usage
`./dso-log-scrubber [params]`

## Parameters
- `-h`: Show help message and exit
- `--patterns`: List of regular expression patterns to find sensitive data.
- `--replace_with`: Text to replace sensitive data with.  Use 
- `--inplace`: Overwrite the input file with the sanitized output.
- `--encoding`: Specify the encoding of the input file. If not provided, encoding will be auto-detected.

## License
Copyright (c) ShadowStrikeHQ
