import { TAgent, IMessageHandler, IDIDManager, ICredentialPlugin } from '@veramo/core-types'
import { ISDJwtPlugin } from '../../src/types/ISDJwtPlugin.js'

import { jest } from '@jest/globals'

type ConfiguredAgent = TAgent<ISDJwtPlugin & IMessageHandler & IDIDManager & ICredentialPlugin>

export default (testContext: {
  getAgent: () => ConfiguredAgent
  setup: () => Promise<boolean>
  tearDown: () => Promise<boolean>
}) => {
  describe('my plugin events', () => {
    let agent: ConfiguredAgent

    beforeAll(async () => {
      await testContext.setup()
      agent = testContext.getAgent()
    })

    afterAll(async () => {
      await testContext.tearDown()
    })

    // This plugin has no events
  })
}
