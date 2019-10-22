var async = require('async');

module.exports = function(GitHubConfig, octokit, collection, callback) {
    if (!collection.apps ||
        !collection.apps.listRepos ||
        !collection.apps.listRepos.data) {
        collection.repos.listCollaborators = {};
        return callback();
    }

    var repos = collection.apps.listRepos.data;
    var owner = GitHubConfig.login;

    async.eachLimit(repos, 5, function(repoObj, cb){
        var repo = repoObj.name;
        collection.repos.listCollaborators[repo] = {};

        var options = octokit['repos']['listCollaborators'].endpoint.merge({owner, repo});
        
        octokit.paginate(options).then(function(results){
            if (results) collection.repos.listCollaborators[repo].data = results;
            cb();
        }, function(err){
            if (err) collection.repos.listCollaborators[repo].err = err;
            cb();
        });
    }, function(){
        callback();
    });
};
