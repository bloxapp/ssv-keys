"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseCommand = void 0;
const tslib_1 = require("tslib");
const prompts_1 = tslib_1.__importDefault(require("prompts"));
const argparse_1 = require("argparse");
class BaseCommand extends argparse_1.ArgumentParser {
    /**
     * @param interactive if the command should be interactive instead of classic CLI
     * @param options argparse options
     */
    constructor(interactive = false, options = undefined) {
        super(options);
        /**
         * List of all supported command actions.
         * @protected
         */
        this.actions = [];
        this.actionParsers = {};
        this.subParserOptions = {
            title: 'Actions',
            description: 'Possible actions',
            help: 'To get more detailed help: "<action> --help". ',
        };
        this.interactive = false;
        this.interactive = interactive;
    }
    /**
     * Add actions sub-parsers.
     */
    addActionsSubParsers() {
        this.subParsers = this.add_subparsers(this.subParserOptions);
        for (const action of this.actions) {
            const actionOptions = action.options;
            const actionParser = this.subParsers.add_parser(actionOptions.action, {
                aliases: [actionOptions.shortAction]
            });
            for (const argument of actionOptions.arguments) {
                actionParser.add_argument(argument.arg1, argument.arg2, argument.options);
            }
            actionParser.set_defaults({
                func: (args) => {
                    const executable = new action();
                    return executable.setArgs(args).execute();
                },
            });
            this.actionParsers[actionOptions.action] = actionParser;
        }
        return this;
    }
    /**
     * Interactively ask user for action
     */
    askAction() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const response = yield (0, prompts_1.default)({
                type: 'select',
                name: 'action',
                message: `Select action`,
                choices: this.actions.map((action) => {
                    return { title: action.options.description, value: action.options.action };
                }),
            });
            return response.action;
        });
    }
    /**
     * Interactively ask user for action to execute, and it's arguments.
     * Populate process.argv with user input.
     */
    executeInteractive() {
        var _a, _b;
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            // Ask for action
            const selectedAction = yield this.askAction();
            selectedAction || process.exit(1);
            process.argv.push(selectedAction);
            const processedArguments = {};
            const actionArguments = this.getArgumentsForAction(selectedAction);
            for (const argument of actionArguments) {
                const multi = {};
                const repeats = ((_a = argument.interactive) === null || _a === void 0 ? void 0 : _a.repeat) || 1;
                const promptOptions = this.getPromptOptions(argument);
                if (processedArguments[promptOptions.name]) {
                    continue;
                }
                processedArguments[promptOptions.name] = true;
                const message = promptOptions.message;
                const extraOptions = { onSubmit: promptOptions.onSubmit };
                for (let i = 1; i <= repeats; i++) {
                    promptOptions.message = repeats > 1 ? `${message}: ${i} from ${repeats}` : message;
                    const response = yield (0, prompts_1.default)(promptOptions, extraOptions);
                    this.assertRequired(argument, response[promptOptions.name]);
                    multi[promptOptions.name] = multi[promptOptions.name] || [];
                    multi[promptOptions.name].push(response[promptOptions.name]);
                    // Processing "repeatWith".
                    // For cases when some parameters are relative to each other and should be
                    // asked from user in a relative way.
                    if (repeats > 1 && ((_b = argument.interactive) === null || _b === void 0 ? void 0 : _b.repeatWith)) {
                        for (const extraArgumentName of argument.interactive.repeatWith) {
                            const extraArgument = this.findArgumentByName(extraArgumentName, actionArguments);
                            if (!extraArgument) {
                                continue;
                            }
                            // Build extra argument options
                            const extraArgumentPromptOptions = this.getPromptOptions(extraArgument);
                            if (processedArguments[extraArgumentPromptOptions.name]
                                && processedArguments[extraArgumentPromptOptions.name] === repeats) {
                                continue;
                            }
                            const extraArgumentMessage = extraArgumentPromptOptions.message;
                            const extraArgumentOptions = { onSubmit: extraArgumentPromptOptions.onSubmit };
                            extraArgumentPromptOptions.message = `${extraArgumentMessage}: ${i} from ${repeats}`;
                            // Prompt extra argument
                            const response = yield (0, prompts_1.default)(extraArgumentPromptOptions, extraArgumentOptions);
                            this.assertRequired(extraArgument, response[extraArgumentPromptOptions.name]);
                            multi[extraArgumentPromptOptions.name] = multi[extraArgumentPromptOptions.name] || [];
                            multi[extraArgumentPromptOptions.name].push(response[extraArgumentPromptOptions.name]);
                            processedArguments[extraArgumentPromptOptions.name] = processedArguments[extraArgumentPromptOptions.name] || 0;
                            processedArguments[extraArgumentPromptOptions.name] += 1;
                        }
                    }
                }
                for (const argumentName of Object.keys(multi)) {
                    process.argv.push(`${argumentName}=${multi[argumentName].join(',')}`);
                }
            }
        });
    }
    /**
     * Find argument in list of arguments by its arg2 value.
     * @param extraArgumentName
     * @param actionArguments
     */
    findArgumentByName(extraArgumentName, actionArguments) {
        for (const argument of actionArguments) {
            if (extraArgumentName === argument.arg2) {
                return argument;
            }
        }
        return null;
    }
    /**
     * Returns list of arguments for selected user action
     * @param userAction
     */
    getArgumentsForAction(userAction) {
        for (const action of this.actions) {
            if (action.options.action === userAction) {
                return action.options.arguments;
            }
        }
        return null;
    }
    /**
     * Compile final prompt options
     * @param argument
     */
    getPromptOptions(argument) {
        var _a, _b, _c, _d, _e;
        const message = ((_b = (_a = argument.interactive) === null || _a === void 0 ? void 0 : _a.options) === null || _b === void 0 ? void 0 : _b.message) || argument.options.help;
        return Object.assign(Object.assign({}, ((_c = argument.interactive) === null || _c === void 0 ? void 0 : _c.options) || {}), { type: ((_e = (_d = argument.interactive) === null || _d === void 0 ? void 0 : _d.options) === null || _e === void 0 ? void 0 : _e.type) || 'text', name: argument.arg2, message, onSubmit: argument.interactive.onSubmit || undefined });
    }
    /**
     * If argument is required but value didn't provide by user - exit process with error code.
     * @param argument
     * @param value
     */
    assertRequired(argument, value) {
        var _a, _b;
        if (argument.options.required && !value) {
            console.error(`Parameter is required: ${((_b = (_a = argument.interactive) === null || _a === void 0 ? void 0 : _a.options) === null || _b === void 0 ? void 0 : _b.message) || argument.options.help}`);
            process.exit(1);
        }
    }
    execute() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            // Interactive execution
            if (this.interactive) {
                yield this.executeInteractive();
            }
            // Non-interactive execution
            // Add actions
            this.addActionsSubParsers();
            // Execute action
            const args = this.parse_args();
            return args.func(args);
        });
    }
}
exports.BaseCommand = BaseCommand;
//# sourceMappingURL=BaseCommand.js.map