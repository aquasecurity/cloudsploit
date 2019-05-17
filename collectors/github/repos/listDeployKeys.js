var async = require('async');

module.exports = function(GitHubConfig, octokit, collection, callback) {
    var repos = GitHubConfig.organization ? collection.repos.listForOrg : collection.repos.list;
    var owner = GitHubConfig.login;

    console.log(repos);

    async.eachLimit(repos.data, 15, function(repoObj, cb){
        var repo = repoObj.name;
        collection.repos.listDeployKeys[repo] = {};
        console.log(repo);

        octokit['token']['repos']['listDeployKeys']({owner, repo}).then(function(results){
            if (repo === 'blasze') console.log(results);
            if (results && results.data) collection.repos.listDeployKeys[repo].data = results.data;
            cb();
        }, function(err){
            if (repo === 'blasze') console.log(err);
            if (err) collection.repos.listDeployKeys[repo].err = err;
            cb();
        });
    }, function(){
        callback();
    });
};
