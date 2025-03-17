import inquirer from 'inquirer'
import {readdirSync} from 'node:fs'
import path from 'node:path'
import {fork} from 'node:child_process'

const unitDir: string = path.resolve(__dirname, './units')
const unitModules: string[] = readdirSync(unitDir).filter(unit => unit.endsWith('spec.js')).map(unit => path.resolve(unitDir, unit))

inquirer
    .prompt([
        {
            type: 'list',
            name: 'unit',
            message: 'Select an unit to test',
            choices: unitModules.map(unitPath => path.basename(unitPath, '.spec.js'))
        }
    ])
    .then(async (answers) => {
        const [selectedModule] = unitModules.filter(unitPath => path.basename(unitPath, '.spec.js') === answers.unit)
        fork(selectedModule)
    })
    .catch(console.error)
