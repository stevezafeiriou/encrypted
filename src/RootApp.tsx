import { Suspense, lazy } from 'react'
import { BrowserRouter } from 'react-router-dom'

import AppSkeleton from './AppSkeleton.tsx'

const App = lazy(() => import('./App.tsx'))

export default function RootApp() {
  return (
    <BrowserRouter>
      <Suspense fallback={<AppSkeleton />}>
        <App />
      </Suspense>
    </BrowserRouter>
  )
}
