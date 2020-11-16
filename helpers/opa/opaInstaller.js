// Installs the opa engine based on the user OS
const os = require('os');
const fs = require('fs');
const  https = require('https');
const request = require('request');
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

var downloadOPAforOscurl = () => {
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
}

var downloadOPAforOs = (callback) => {
    var osType = os.type();
    var opaurl;
    var opapath;
    if ( osType === 'Windows_NT' ){
        opaurl = "https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe";
        opapath = 'opa.exe';
        // command = 'dir';
    } else if ( osType === 'Linux' ){
        //opaurl = "https://openpolicyagent.org/downloads/latest/opa_linux_amd64";
        //opapath = 'opa'
    } else if ( osType === 'Darwin' ){
        //opaurl = "https://openpolicyagent.org/downloads/latest/opa_darwin_amd64";
        //opapath = 'opa';
    }
    var file = fs.createWriteStream(opapath);

    var request = https.get(opaurl, function(response) {
        response.pipe(file);
        file.on('finish', function() {
            file.close(callback);  // close() is async, call cb after close completes.
        });
    }).on('error', function(err) { // Handle errors
        console.error(err.message);
        fs.unlink(opapath); // Delete the file async. (But we don't check the result)
        if (callback) callback(err.message);
    });

    console.log('calling request')
    // request({
    //     uri: opaurl,
    //     method: 'GET'},
    //     function (error, response, body) {
    //     console.log('after request');
    //     console.error('error:', error); // Print the error if one occurred
    //     console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
    //     console.log('body:', body);
    //     var file = fs.createWriteStream(opapath);
    //     response.pipe(file);
    //     file.on('finish', function () {
    //         file.close(callback); // close() is async, call callback after close completes.
    //     });
    //     file.on('error', function (err) {
    //         fs.unlink(opapath); // Delete the file async. (But we don't check the result)
    //         if (callback)
    //             callback(err.message);
    //     });
    // });
}


var runOPAEal = () =>{};

module.exports = {
    downloadOPAforOs: downloadOPAforOscurl,
    executeCommand: executeCommand
};
