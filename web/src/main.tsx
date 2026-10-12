import React from 'react';
import {createRoot} from 'react-dom/client';
import App from './App';
import {readTheme,applyTheme} from './theme';
import './style.css';
import './themes.css';

applyTheme(readTheme());
createRoot(document.getElementById('root')!).render(<App/>);
