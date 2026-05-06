#!/usr/bin/env node
import { program } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import figlet from 'figlet';
import path from 'path';

import { loadTargets, isBrowserHeaded, getScanTimeout, getReportsDir } from '../core/config';
import { Scanner } from '../core/scanner';
import { HtmlReporter } from '../reporter/html.reporter';
import { listPlugins } from '../plugins/registry';
import { PluginId, ScanOptions, SurfaceType } from '../types';

const ALL_PLUGIN_IDS: PluginId[] = [
  'sql-injection',
  'nosql-injection',
  'xss',
  'ssti',
  'prototype-pollution',
];

const ALL_SURFACE_IDS: SurfaceType[] = ['form', 'query-param', 'header', 'api-body'];

function printBanner(): void {
  console.log(
    chalk.red(
      figlet.textSync('CVEBox', { font: 'Big', horizontalLayout: 'default' })
    )
  );
  console.log(
    chalk.gray('  Security Scanner for Web Applications · QA Edition\n')
  );
}

function printPluginList(): void {
  const plugins = listPlugins();
  console.log(chalk.bold('\n  Available Plugins:\n'));
  plugins.forEach((p, i) => {
    console.log(`  ${chalk.cyan(`${i + 1}.`)} ${chalk.bold(p.name)}`);
    console.log(`     ${chalk.gray(p.description)}\n`);
  });
}

async function promptScanOptions(): Promise<{
  selectedPlugins: PluginId[];
  selectedSurfaces: SurfaceType[];
  headed: boolean;
}> {
  const pluginChoices = listPlugins().map((p) => ({
    name: `${p.name} — ${p.description}`,
    value: p.id,
    checked: true,
  }));

  const surfaceChoices = [
    { name: 'HTML Forms (input fields, textareas)', value: 'form', checked: true },
    { name: 'Query Parameters (GET params in URL)', value: 'query-param', checked: true },
    { name: 'HTTP Headers (X-Forwarded-For, Referer, etc.)', value: 'header', checked: false },
    { name: 'API Body (JSON POST/PUT/PATCH)', value: 'api-body', checked: false },
  ];

  const answers = await inquirer.prompt([
    {
      type: 'checkbox',
      name: 'plugins',
      message: 'Which security tests do you want to run?',
      choices: pluginChoices,
      validate: (input: PluginId[]) =>
        input.length > 0 ? true : 'Select at least one test.',
    },
    {
      type: 'checkbox',
      name: 'surfaces',
      message: 'Which attack surfaces should be tested?',
      choices: surfaceChoices,
      validate: (input: SurfaceType[]) =>
        input.length > 0 ? true : 'Select at least one surface.',
    },
    {
      type: 'confirm',
      name: 'headed',
      message: 'Run browser in HEADED mode (visible window)?',
      default: false,
    },
  ]);

  return {
    selectedPlugins: answers.plugins as PluginId[],
    selectedSurfaces: answers.surfaces as SurfaceType[],
    headed: answers.headed as boolean,
  };
}

async function runScan(options: ScanOptions): Promise<void> {
  const targets = loadTargets();
  const scanner = new Scanner();
  const reporter = new HtmlReporter();
  const reportsDir = getReportsDir();

  console.log(
    chalk.bold(`\n  Scanning ${targets.length} target(s)...\n`)
  );

  const reportPaths: string[] = [];

  for (const target of targets) {
    const result = await scanner.scan(target, options);
    const reportPath = reporter.generate(result, reportsDir);
    reportPaths.push(reportPath);

    console.log(
      chalk.bold(`\n  Report saved → `) + chalk.underline(reportPath)
    );
  }

  console.log(chalk.bold.green('\n  ✓ All scans completed.\n'));
  console.log(chalk.bold('  Reports generated:'));
  reportPaths.forEach((p) => console.log(`    · ${p}`));
  console.log('');
}

async function interactiveMenu(): Promise<void> {
  printBanner();

  const mainAnswer = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { name: '🔍  Run Security Scan', value: 'scan' },
        { name: '📋  List Available Plugins', value: 'list' },
        { name: '⚙️   Run All Tests (quick scan)', value: 'all' },
        { name: '❌  Exit', value: 'exit' },
      ],
    },
  ]);

  switch (mainAnswer.action) {
    case 'scan': {
      const { selectedPlugins, selectedSurfaces, headed } =
        await promptScanOptions();
      const options: ScanOptions = {
        plugins: selectedPlugins,
        surfaces: selectedSurfaces,
        headed,
        timeout: getScanTimeout(),
        pipeline: false,
      };
      await runScan(options);
      break;
    }

    case 'list': {
      printPluginList();
      await interactiveMenu();
      break;
    }

    case 'all': {
      console.log(chalk.yellow('\n  Running all plugins on all surfaces...\n'));
      const options: ScanOptions = {
        plugins: ALL_PLUGIN_IDS,
        surfaces: ALL_SURFACE_IDS,
        headed: isBrowserHeaded(),
        timeout: getScanTimeout(),
        pipeline: false,
      };
      await runScan(options);
      break;
    }

    case 'exit':
      console.log(chalk.gray('\n  Goodbye.\n'));
      process.exit(0);
  }
}

async function pipelineMode(opts: {
  plugins?: string;
  surfaces?: string;
  headed: boolean;
}): Promise<void> {
  const selectedPlugins: PluginId[] =
    opts.plugins === 'all' || !opts.plugins
      ? ALL_PLUGIN_IDS
      : (opts.plugins.split(',').map((s) => s.trim()) as PluginId[]);

  const selectedSurfaces: SurfaceType[] =
    opts.surfaces === 'all' || !opts.surfaces
      ? ALL_SURFACE_IDS
      : (opts.surfaces.split(',').map((s) => s.trim()) as SurfaceType[]);

  const options: ScanOptions = {
    plugins: selectedPlugins,
    surfaces: selectedSurfaces,
    headed: opts.headed,
    timeout: getScanTimeout(),
    pipeline: true,
  };

  await runScan(options);
}

program
  .name('cvebox')
  .version('1.0.0')
  .description('CVEBox — Security scanner for web applications (QA Edition)')
  .option('--pipeline', 'Run in pipeline mode (no interactive menu)')
  .option('--plugins <list>', 'Comma-separated plugin IDs or "all"', 'all')
  .option('--surfaces <list>', 'Comma-separated surfaces or "all"', 'all')
  .option('--headed', 'Launch browser in headed (visible) mode', false)
  .action(async (options) => {
    try {
      if (options.pipeline) {
        await pipelineMode({
          plugins: options.plugins,
          surfaces: options.surfaces,
          headed: options.headed,
        });
      } else {
        await interactiveMenu();
      }
    } catch (err: unknown) {
      console.error(chalk.red('\n  [ERROR] ' + (err instanceof Error ? err.message : String(err))));
      process.exit(1);
    }
  });

program.parse(process.argv);
