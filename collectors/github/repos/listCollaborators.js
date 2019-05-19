var async = require('async');

module.exports = function(GitHubConfig, octokit, collection, callback) {
    if (!collection.apps ||
        !collection.apps.listRepos ||
        !collection.apps.listRepos.data ||
        !collection.apps.listRepos.data.repositories) {
        collection.repos.listCollaborators = {};
        return callback();
    }

    var repos = collection.apps.listRepos.data.repositories;
    var owner = GitHubConfig.login;

    async.eachLimit(repos, 15, function(repoObj, cb){
        var repo = repoObj.name;
        collection.repos.listCollaborators[repo] = {};

        octokit['repos']['listCollaborators']({owner, repo}).then(function(results){
            if (results && results.data) collection.repos.listCollaborators[repo].data = results.data;
            cb();
        }, function(err){
            if (err) collection.repos.listCollaborators[repo].err = err;
            cb();
        });
    }, function(){
        callback();
    });
};
