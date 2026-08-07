import { useEffect, useState, createContext, useContext } from 'react'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { api, Me } from './api'
import LoginPage from './pages/Login'
import RegisterPage from './pages/Register'
import NodesPage from './pages/Nodes'
import SelectNodePage from './pages/SelectNode'
import AdminPage from './pages/Admin'
import AdminLoginPage from './pages/AdminLogin'

interface AuthCtx {
  me: Me | null
  loading: boolean
  refresh: () => Promise<void>
  setMe: (m: Me | null) => void
}

const Ctx = createContext<AuthCtx>({ me: null, loading: true, refresh: async () => {}, setMe: () => {} })
export const useAuth = () => useContext(Ctx)

export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    try {
      const m = await api.me()
      setMe(m)
    } catch {
      setMe(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])

  return (
    <Ctx.Provider value={{ me, loading, refresh, setMe }}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/select-node" element={<SelectNodePage />} />
        <Route path="/admin/login" element={<AdminLoginPage />} />
        <Route path="/admin/*" element={<AdminPage />} />
        <Route
          path="/"
          element={
            loading ? <div className="loading">加载中…</div>
              : me?.is_admin ? <Navigate to="/admin" replace />
              : me ? <NodesPage />
              : <Navigate to="/login" replace />
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Ctx.Provider>
  )
}
