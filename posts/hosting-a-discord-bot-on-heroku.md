= yaml =
title: Hosting a Discord bot on Heroku
slug: hosting-a-discord-bot-on-heroku
date: 19/03/2019
tags: development,project
= yaml =

## Overview

After searching around for a Discord Japanese-Japanese dictionary bot and failing to find one, I decided to [make my own](https://github.com/josephsurin/shinmeikai)! I've made Discord bots before using Node.js ([artoria-bot](https://github.com/josephsurin/artoria-bot) [yuyu-chan](https://github.com/josephsurin/yuyu-chan)), so to mix things up a bit and to practice Python, I wrote my dictionary bot in Python, using the [discord.py](https://github.com/Rapptz/discord.py) API wrapper.

The actual code for the bot is not all that interesting, in this post I'll talk about how to get a simple Discord bot set up and running on [Heroku](https://www.heroku.com/).

### Prerequisites

- A [Heroku account](https://signup.heroku.com/) (free)
- The [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli#download-and-install)
- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

### Setting up the bot

At the very minimum, your project should have a `main.py` file which contains the code to start your bot. discord.py has [excellent documentation](https://discordpy.readthedocs.io/en/latest/api.html) to help you with this.

To let Discord know what bot is being run, you'll need a secret token issued by Discord. This can be obtained from the developer portal when you create your Discord application. Make sure only you see this token! If someone else gets access to this token, they could run their own code as your bot, potentially causing a lot of damage to the servers your bot is in. To ensure the safety of your token, consider using [environment variables](https://en.wikipedia.org/wiki/Environment_variable).

If you're using discord.py, then you're requiring Python code from outside the standard library. [pip](https://pip.pypa.io/en/stable/) is Python's package installer and helps to make dealing with external dependencies easier. You'll want to make a [Requirements File](https://pip.pypa.io/en/stable/user_guide/?highlight=Requirements#requirements-files) which Heroku will use to automatically install the requirements for your bot.

To get the invite link for your bot, use [this tool](https://discordapi.com/permissions.html).

### The Process

Once you've got a Heroku account and the necessary tools set up, deploying the bot is a fairly straightforward process.

After installing the Heroku CLI, run the `heroku login` command in a terminal and enter your details to log in to your Heroku account.

Make sure you're using git for version control for your project as Heroku requires it. If you aren't, run the `git init` command to set up the git repository.

After logging in to Heroku through the CLI, you'll be able to issue the `heroku create` command in the root of your project. This will add your Heroku app's remote repo url to your git repository so that you can deploy your code.

To deploy, simply run `git push heroku master`.

And that's it!

... sort of

### The Details

You may have noticed that 'deploying' your code to Heroku did nothing! Although your code is up on the Heroku servers and all the packages have been installed on the remote machine, Heroku doesn't know what to do with it. To let Heroku know what to do, you'll need a [Procfile](https://devcenter.heroku.com/articles/procfile). The Procfile is a simple text file named `Procfile` (exactly that) at the root of your project that specifies what commands are to  be executed upon startup.

If you've got your bot's code in `main.py` then writing `worker: python main.py` to your Procfile will run your bot on Heroku, assuming you've got a [dyno](https://www.heroku.com/dynos) running. To add a worker dyno, simply run `heroku ps:scale worker=1`.

Now if you `git add` and `git commit` the new Procfile and `git push heroku master` it, your bot should be up and running!  