var csvWriter = require('csv-write-stream');
var fs = require('fs');

// For the console output, we don't need any state since we can write
// directly to the console.
var consoleOutputHandler = {
    startCompliance: function(plugin, pluginKey, compliance) {
        var complianceDesc = compliance.describe(pluginKey, plugin);
        if (complianceDesc) {
            console.log('');
            console.log('-----------------------');
            console.log(plugin.title);
            console.log('-----------------------');
            console.log(complianceDesc);
            console.log('');
        }
    },

    endCompliance: function(plugin, pluginKey, compliance) {
        // For console output, we don't do anything
    },

    writeResult: function (result, plugin, pluginKey) {
        var statusWord;
        if (result.status === 0) {
            statusWord = 'OK';
        } else if (result.status === 1) {
            statusWord = 'WARN';
        } else if (result.status === 2) {
            statusWord = 'FAIL';
        } else {
            statusWord = 'UNKNOWN';
        }

        console.log(plugin.category + '\t' + plugin.title + '\t' +
                        (result.resource || 'N/A') + '\t' +
                        (result.region || 'Global') + '\t\t' +
                        statusWord + '\t' + result.message);
    },

    close: function() {}
}

module.exports = {
    /**
     * Creates an output handler that writes output in the CSV format.
     * @param {fs.WriteSteam} stream The stream to write to or an object that
     * obeys the writeable stream contract.
     */
    createCsv: function (stream) {
        var writer = csvWriter({headers: ['category', 'title', 'resource',
                                          'region', 'statusWord', 'message']});
        writer.pipe(stream);

        return {
            writer: writer,
        
            startCompliance: function(plugin, pluginKey, compliance) {
            },
        
            endCompliance: function(plugin, pluginKey, compliance) {
            },
        
            writeResult: function (result, plugin, pluginKey) {
                var statusWord;
                if (result.status === 0) {
                    statusWord = 'OK';
                } else if (result.status === 1) {
                    statusWord = 'WARN';
                } else if (result.status === 2) {
                    statusWord = 'FAIL';
                } else {
                    statusWord = 'UNKNOWN';
                }
        
                this.writer.write([plugin.category, plugin.title,
                                   (result.resource || 'N/A'),
                                   (result.region || 'Global'),
                                   statusWord, result.message]);
            },
        
            close: function () {
                this.writer.end();
            }
        }
    },

    /**
     * Creates an output handler that writes output in the JSON format.
     * @param {fs.WriteSteam} stream The stream to write to or an object that
     * obeys the writeable stream contract.
     */
    createJson: function (stream) {
      var results = [];
      return {
          stream: stream,
      
          startCompliance: function(plugin, pluginKey, compliance) {
          },
      
          endCompliance: function(plugin, pluginKey, compliance) {
          },
      
          writeResult: function (result, plugin, pluginKey) {
              var statusWord;
              if (result.status === 0) {
                  statusWord = 'OK';
              } else if (result.status === 1) {
                  statusWord = 'WARN';
              } else if (result.status === 2) {
                  statusWord = 'FAIL';
              } else {
                  statusWord = 'UNKNOWN';
              }
              
              results.push({
                plugin: pluginKey,
                category: plugin.category,
                title: plugin.title,
                resource: result.resource || 'N/A',
                region: result.region || 'Global',
                status: statusWord,
                message: result.message
              })
          },
      
          close: function () {
            this.stream.write(JSON.stringify(results));              
            this.stream.end();
          }
      }
  },

    /***
     * Creates an output handler that writes output in the JUnit XML format.
     * 
     * This constructs the XML directly, rather than through a library so that
     * we don't need to pull in another NPM dependency. This keeps things
     * simple.
     * 
     * @param {fs.WriteStream} stream The stream to write to or an object that
     * obeys the writeable stream contract.
     */
    createJunit: function (stream) {
        return {
            stream: stream,
        
            /**
             * The test suites are how we represent result - each test suite
             * maps to one plugin (more specifically the plugin key) so that
             * we group tests based on the plugin key.
             */
            testSuites: {},

            startCompliance: function(plugin, pluginKey, compliance) {
            },
        
            endCompliance: function(plugin, pluginKey, compliance) {
            },
        
            /**
             * Adds the result to be written to the output file.
             */
            writeResult: function (result, plugin, pluginKey) {
                var suiteName = pluginKey;
                if (!this.testSuites.hasOwnProperty(suiteName)) {
                    // The time to report for the tests (since we don't have
                    // time for any of them.) The expected JUnit format doesn't
                    // allow for time or MS, so omit those
                    var time = (new Date()).toISOString();
                    time = time.substr(0, time.indexOf('.'));

                    this.testSuites[suiteName] = {
                        name: plugin.title + ': ' + (plugin.description || ''),
                        package: pluginKey,
                        failures: 0,
                        errors: 0,
                        testCases: [],
                        time: time
                    };
                }

                // Get the test suite that we want to add to
                var testSuite = this.testSuites[pluginKey];

                // Was this test an error or failure?
                var failure = result.status === 2 ? (result.message || 'Unexpected failure') : undefined;
                testSuite.failures += failure ? 1 : 0;
                var error = result.status > 2 ? (result.message || 'Unexpected error') : undefined;
                testSuite.errors += error ? 1 : 0;

                // Each plugin can generate multiple results, which we map as
                // one plugin to one test suite. Each result in that suite needs
                // to have enough context to be useful (even for passes), so
                // we add all of that that information at the name of the test
                var name = result.region + '; ' + (result.resource || 'N/A') + '; ' + result.message;

                testSuite.testCases.push({
                    name: name,
                    classname: pluginKey,
                    file: '',
                    line: 0,
                    failure: failure,
                    error: error
                });
            },
        
            /**
             * Closes the output handler. For this JUnit output handler, all of
             * the work happens on close since we need to know information
             * about results upfront.
             */
            close: function () {
                this.stream.write('<?xml version="1.0" encoding="UTF-8" ?>\n');
                this.stream.write('<testsuites>\n');

                var index = 0;
                for (var key in this.testSuites) {
                    this._writeSuite(this.testSuites[key], index);
                    index += 1;
                }

                this.stream.write('</testsuites>\n');
                
                this.stream.end();
            },

            /**
             * Writes the test suite to the output stream. This should really
             * only be called internally by this class.
             * @param testSuite The test suite to write to the stream
             */
            _writeSuite: function (testSuite, index)  {
                var numTests = testSuite.testCases.length;

                this.stream.write('\t<testsuite name="' + testSuite.name +
                                  '" hostname="localhost" tests="' + numTests +
                                  '" errors="' + testSuite.errors +
                                  '" failures="' + testSuite.failures +
                                  '" timestamp="' + testSuite.time +
                                  '" time="0" package="' + testSuite.package +
                                  '" id="' + index + '">\n');

                // The schema says we must have the properties element, but it can be empty
                this.stream.write('\t\t<properties></properties>\n');
                for (var testCase of testSuite.testCases) {
                    this.stream.write('\t\t<testcase classname="' +
                                      testCase.classname +'" name="' +
                                      testCase.name + '" time="0"');

                    // If we need a child, then write that, otherwise close
                    // of the test case without creating an unnecessary text
                    // element
                    if (testCase.failure) {
                        this.stream.write('>\n\t\t\t<failure message="' +
                                          testCase.failure + '" type="none"/>\n' +
                                          '\t\t</testcase>\n');
                    } else if (testCase.error) {
                        this.stream.write('>\n\t\t\t<failure message="' +
                                          testCase.error + '" type="none"/>\n' +
                                          '\t\t</testcase>\n');
                    } else {
                        this.stream.write('/>\n');
                    }
                    
                }

                // Same thing with properties above - this just needs to exist
                // even if we don't have data (according to the schema)
                this.stream.write('\t\t<system-out></system-out>\n');
                this.stream.write('\t\t<system-err></system-err>\n');

                this.stream.write('\t</testsuite>\n');
            }
        }
    },

    /**
     * Creates an output handler depending on the arguments list as expected
     * in the command line format. If multiple output handlers are specified
     * in the arguments, then constructs a unified view so that it appears that
     * there is only one output handler.
     * 
     * @param {string[]} argv Array of command line arguments (may contain
     * arguments that are not relevant to constructing output handlers).
     * 
     * @return A object that obeys the output handler contract. This may be
     * one output handler or one that forwards function calls to a group of
     * output handlers.
     */
    create: function (argv) {
        var outputs = [];

        // Creates the handlers for writing output.
        var addCsvOutput = argv.find(function (arg) {
            return arg.startsWith('--csv=');
        })
        if (addCsvOutput) {
            var stream = fs.createWriteStream(addCsvOutput.substr(6));
            outputs.push(this.createCsv(stream));
        }

        var addJunitOutput = argv.find(function (arg) {
            return arg.startsWith('--junit=');
        })
        if (addJunitOutput) {
            var stream = fs.createWriteStream(addJunitOutput.substr(8));
            outputs.push(this.createJunit(stream));
        }

        var addConsoleOutput = argv.find(function (arg) {
            return arg.startsWith('--console');
        })
        // Write to console if specified or by default if there is not
        // other output handler specified.
        if (addConsoleOutput || outputs.length == 0) {
            outputs.push(consoleOutputHandler);
        }

        // Ignore any "OK" results - only report issues
        var ignoreOkStatus = argv.find(function (arg) {
            return arg.startsWith('--ignore-ok');
        })

        // This creates a multiplexer-like object that forwards the
        // call onto any output handler that has been defined. This
        // allows us to simply send the output to multiple handlers
        // and the caller doesn't need to worry about that part.
        return {
            startCompliance: function(plugin, pluginKey, compliance) {
                for (var output of outputs) {
                    output.startCompliance(plugin, pluginKey, compliance);
                }
            },

            endCompliance: function(plugin, pluginKey, compliance) {
                for (var output of outputs) {
                    output.endCompliance(plugin, pluginKey, compliance);
                }
            },

            writeResult: function (result, plugin, pluginKey) {
                for (var output of outputs) {
                    if (!(ignoreOkStatus && result.status === 0)) {
                        output.writeResult(result, plugin, pluginKey);
                    }
                }
            },

            close: function () {
                for (var output of outputs) {
                    output.close();
                }
            }
        }
    }
}
