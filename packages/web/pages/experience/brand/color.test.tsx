import * as React from 'react'
import * as renderer from 'react-test-renderer'
import Color from './color'

describe('Experience/Color', () => {
  it('renders', () => {
    const tree = renderer.create(<Color />).toJSON()
    expect(tree).toMatchSnapshot()
  })
})