export default defineAppConfig({
  pages: [
    'pages/index/index',
    'pages/discovery/index',
    'pages/history/index',
    'pages/chat/index'
  ],
  window: {
    backgroundTextStyle: 'light',
    navigationBarBackgroundColor: '#1a1a2e',
    navigationBarTitleText: 'NetProwl',
    navigationBarTextStyle: 'white'
  },
  tabBar: {
    color: '#999',
    selectedColor: '#00d4ff',
    backgroundColor: '#1a1a2e',
    borderStyle: 'black',
    list: [
      { pagePath: 'pages/index/index', text: '发现', iconPath: 'assets/tab-discovery.png', selectedIconPath: 'assets/tab-discovery-active.png' },
      { pagePath: 'pages/history/index', text: '历史', iconPath: 'assets/tab-history.png', selectedIconPath: 'assets/tab-history-active.png' },
      { pagePath: 'pages/chat/index', text: '问诊', iconPath: 'assets/tab-chat.png', selectedIconPath: 'assets/tab-chat-active.png' }
    ]
  }
})
