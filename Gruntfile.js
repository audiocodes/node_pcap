module.exports = function(grunt) {
    var src = ["*.js", "decode/**/*.js"];
    var tests = ["spec/**/*.js"];
    var supportingFiles = ["Gruntfile.js"];
    var allJs = tests.concat(src);
    grunt.initConfig({
        eslint: {
            target: "*.js"
        },
        mochaTest: {
            test: {
                src: allJs,
            }
        },
        mocha_istanbul: {
            coverage: {
                src: allJs,
                options: {
                    reportFormats: ["text", "html", "lcov"],
                    excludes: tests.concat(supportingFiles)
                }
            }
        },
    });

    grunt.loadNpmTasks("grunt-mocha-test");
    grunt.loadNpmTasks("grunt-eslint");
    grunt.loadNpmTasks("grunt-mocha-istanbul");

    //Check code coverage with grunt cover
    grunt.registerTask("cover", ["mocha_istanbul:coverage"]);

    //Just run grunt for day to day work
    grunt.registerTask("default", ["eslint", "mochaTest:test"]);
};
