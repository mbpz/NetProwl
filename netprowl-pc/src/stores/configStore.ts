import { create } from 'zustand';

interface ConfigState {
  deepseekApiKey: string;
  setApiKey: (key: string) => void;
}

export const useConfigStore = create<ConfigState>((set) => ({
  deepseekApiKey: localStorage.getItem('deepseek_api_key') || '',
  setApiKey: (key) => {
    localStorage.setItem('deepseek_api_key', key);
    set({ deepseekApiKey: key });
  },
}));