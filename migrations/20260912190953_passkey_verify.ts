import type { Knex } from 'knex'

export async function up(knex: Knex): Promise<void> {
  await knex.schema.table('passkey', (table) => {
    table.boolean('canVerify').nullable()
  })
  await knex.table('passkey').update({ canVerify: false })
  await knex.schema.table('passkey', (table) => {
    table.dropNullable('canVerify')
  })
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.table('passkey', (table) => {
    table.dropColumn('canVerify')
  })
}
