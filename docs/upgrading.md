# Upgrading CloudSploit
CloudSploit version 2.0.0 introduced a number of changes from the original CloudSploit release, designed to make running CloudSploit easier in multiple environment types, including command line and CI/CD systems.

## Notable Changes
* The addition of the `argparse` library to enhance CLI option support
* Formalizing several previously-hidden settings and options (e.g. saving the JSON collection, multiple output formats, suppressions, etc.)
* The addition of the `tty-table` library for pretty-print CLI output of results. This is now the default output, but it can be changed to text-only via the `--console=text` flag.
* Improved documentation across the AWS, Azure, GCP, and OCI providers.
* The use of a `config.js` file for storing cloud provider configuration options, making it easier to run CloudSploit against multiple accounts by passing the `--config` flag.
* Fallback to the AWS credential chain, allowing users to get started running CloudSploit more quickly.
* Addition of an .eslint file for developers of CloudSploit and CloudSploit plugins.
* Formalizing CIS Benchmark options in the plugins using the `compliance` property.
* Added the ability to run a single plugin directly from the CLI, without editing the `exports.js` file by passing the flag `--plugin pluginName`.

## Preparing Your Environment
If you previously used CloudSploit, you may need to make some changes as part of 2.0. Consider the following steps:
1. If you previously edited the `index.js` file, copy your cloud provider credentials to a new `config.js` file instead. You can do this by:
    ```
    $ cp config_example.js config.js
    // Edit your config.js file and pass either a path to a cloud credential file or the credentials themselves.
    $ ./index.js --config=./config.js
    ```
1. If you are using AWS, you may now use the default credential handler by simply running CloudSploit with no config flag:
    ```
    $ ./index.js
    ```
1. If you were running CloudSploit as part of a CI/CD process, the following flags may be helpful:
    ```
    // Ignore passing results
    $ ./index.js --ignore-ok
    
    // Exit with a non-zero code if non-passing results found
    $ ./index.js --exit-code
    
    // Prints raw text output instead of the pretty-print tables
    $ ./index.js --console=text
    
    // Suppresses the output (only recommended if using a file output)
    $ ./index.js --console=none
    
    // Creates a JUnit XML file
    $ ./index.js --junit=file.xml
    ```
1. If you are running CloudSploit in a place where pretty-print tables, with colors, are not usable, you can revert to raw text output with the `--console=text` flag.
1. The text output has changed. The previous format contained too much information and created unreadable output. The new text output puts each result on its own line, and includes the plugin name, description, and other useful information.
1. If you are using CloudSploit as source input to other systems, we strongly recommend using the JSON output option to create a standardized output file (do not try to parse the output text format). Use `--json=file.json` to create results in a JSON structure.
