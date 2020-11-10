// Installs the opa engine based on the user OS
const os = require('os');
const fs = require('fs');
const { exec,spawn, spawnSync } = require('child_process');

var executeCommand = ( command, options, cb) => {
    exec(command, options, (err, stdout, stderr) => {
        if (err) {
            // node couldn't execute the command
            return cb(err, null, null);
        }
        return cb(null, stdout, stderr);
    });
    // var commandExecutor = exec(command, {timeout:10000, maxBuffer: 2096*2096,encoding: "utf8"});
    //
    // commandExecutor.stdout.on('data', function (data) {
    //     console.log('stdout: ' + data.toString());
    //     cb(data, null);
    // });
    //
    // commandExecutor.stderr.on('data', function (data) {
    //     console.log('stderr: ' + data.toString());
    //     cb(null, data);
    // });
    //
    // commandExecutor.on('exit', function (code) {
    //     console.log('child process exited with code ' + code.toString());
    // });
}

var downloadOPAforOs = () => {
    var osType = os.type();
    var command;
    if ( osType === 'Windows_NT' ){
        command = "curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe";
        // command = 'dir';
    } else if ( osType === 'Linux' ){
        //command = "curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64";
        command = 'ls';
    } else if ( osType === 'Darwin' ){
        //command = "curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64";
        command = 'ls';
    }
    executeCommand(command, {}, (err) => {
        if (err){
            return console.error("Downloading opa failied for OS type " + osType + "with error " + err);
        }
    });
    //return osType;
}

var runOPAEal = () =>{};

module.exports = {
    downloadOPAforOs: downloadOPAforOs,
    executeCommand: executeCommand
};
