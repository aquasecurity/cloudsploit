module.exports = {
    create: function (argv) {
        // Creates an object that can post process results to suppress rules
        // This allows the client to set to ignore particular failures so that
        // they don't affect the overall score
        // Suppressions have the format pluginId:region:resourceId, where any
        // of the items can be * to indicate match all.

        var expressions = argv
            .filter(function (arg) {
                return arg.startsWith('--suppress=');
            })
            .map(function (arg) {
                return arg.substring(11);
            })
            .map(function (expr) {
                return [
                    expr,
                    new RegExp('^' + expr.split('*').join('.*') + '$')
                ];
            });

        return function (result) {
            var match = expressions.find(function (expression) {
                return expression[1].test(result);
            });

            return match && match[0];
        };
    }
};
