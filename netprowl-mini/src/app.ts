import { Component, PropsWithChildren } from 'react'

class App extends Component<PropsWithChildren<any>> {
  componentDidMount() {}

  render() {
    return this.props.children
  }
}

export default App
