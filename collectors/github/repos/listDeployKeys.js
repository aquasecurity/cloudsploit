var async = require('async');

module.exports = function(GitHubConfig, octokit, collection, callback) {
    if (!collection.apps ||
        !collection.apps.listRepos ||
        !collection.apps.listRepos.data) {
        collection.repos.listDeployKeys = {};
        return callback();
    }

    var repos = collection.apps.listRepos.data;
    var owner = GitHubConfig.login;

    async.eachLimit(repos, 5, function(repoObj, cb){
        var repo = repoObj.name;
        collection.repos.listDeployKeys[repo] = {};

        var options = octokit['repos']['listDeployKeys'].endpoint.merge({owner, repo});

        octokit.paginate(options).then(function(results){
            if (results) collection.repos.listDeployKeys[repo].data = results;
            cb();
        }, function(err){
            if (err) collection.repos.listDeployKeys[repo].err = err;
            cb();
        });
    }, function(){
        callback();
    });
};
