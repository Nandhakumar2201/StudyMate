const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://studymate-tkmw.onrender.com/api'

// Helper function to get auth token
const getAuthToken = () => {
  return localStorage.getItem('accessToken')
}

// Helper function to get headers
const getHeaders = (includeAuth = true) => {
  const headers = {
    'Content-Type': 'application/json',
  }
  
  if (includeAuth) {
    const token = getAuthToken()
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
  }
  
  return headers
}

// API Functions
export const api = {
  // Helper to parse JSON response or handle HTML errors
  async parseResponse(response) {
    const contentType = response.headers.get('content-type') || ''
    
    // Clone response to read it safely
    const clonedResponse = response.clone()
    const text = await clonedResponse.text()
    
    // Check if response is JSON
    if (!contentType.includes('application/json')) {
      // Server returned HTML (likely an error page or backend not running)
      if (response.status === 404) {
        throw new Error('Backend endpoint not found. Please check if the Django server is running on http://localhost:8000')
      }
      if (response.status >= 500) {
        throw new Error('Server error. Please check if the backend server is running correctly.')
      }
      if (text.includes('<!DOCTYPE') || text.includes('<html')) {
        throw new Error('Server returned HTML instead of JSON. Please check your backend configuration.')
      }
      throw new Error(`Invalid response from server (${response.status}). Please check your backend connection.`)
    }
    
    try {
      // Parse as JSON
      return JSON.parse(text)
    } catch (parseError) {
      // If JSON parsing fails even though content-type says JSON
      throw new Error(`Failed to parse JSON response: ${text.substring(0, 100)}`)
    }
  },

  // Authentication
  async login(username, email, password) {
    try {
      // Login with email (or username if provided)
      // Backend accepts email in the username field
      const loginData = { username: email || username, password }
      
      const response = await fetch(`${API_BASE_URL}/token/`, {
        method: 'POST',
        headers: getHeaders(false),
        body: JSON.stringify(loginData),
      })
      
      if (!response.ok) {
        const error = await this.parseResponse(response)
        throw new Error(error.detail || error.error || 'Login failed')
      }
      
      return await this.parseResponse(response)
    } catch (error) {
      if (error.message.includes('Backend server') || error.message.includes('Invalid response')) {
        throw error
      }
      // Network error
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Cannot connect to backend server. Please make sure Django is running on http://localhost:8000')
      }
      throw error
    }
  },
  
  async register(userData) {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/register/`, {
        method: 'POST',
        headers: getHeaders(false),
        body: JSON.stringify(userData),
      })
      
      if (!response.ok) {
        const error = await this.parseResponse(response)
        // Handle different error formats
        if (error.error) {
          throw new Error(error.error)
        }
        if (error.detail) {
          throw new Error(error.detail)
        }
        if (typeof error === 'string') {
          throw new Error(error)
        }
        // If error is an object with multiple fields, format them
        const errorMessages = Object.entries(error)
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
          .join('; ')
        throw new Error(errorMessages || 'Registration failed')
      }
      
      return await this.parseResponse(response)
    } catch (error) {
      if (error.message.includes('Backend server') || error.message.includes('Invalid response')) {
        throw error
      }
      // Network error
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Cannot connect to backend server. Please make sure Django is running on http://localhost:8000')
      }
      throw error
    }
  },
  
  // Student APIs
  async getDepartments() {
    const response = await fetch(`${API_BASE_URL}/student/departments/`, {
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to fetch departments')
    }
    return await this.parseResponse(response)
  },
  
  async getYears() {
    const response = await fetch(`${API_BASE_URL}/student/years/`, {
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to fetch years')
    }
    return await this.parseResponse(response)
  },
  
  async getSemesters(filters = {}) {
    const params = new URLSearchParams(filters)
    const response = await fetch(`${API_BASE_URL}/student/semesters/?${params}`, {
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to fetch semesters')
    }
    return await this.parseResponse(response)
  },
  
  async getSubjects(filters = {}) {
    const params = new URLSearchParams(filters)
    const response = await fetch(`${API_BASE_URL}/student/subjects/?${params}`, {
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to fetch subjects')
    }
    return await this.parseResponse(response)
  },
  
  async getMaterials(filters = {}) {
    const params = new URLSearchParams(filters)
    const response = await fetch(`${API_BASE_URL}/student/materials/?${params}`, {
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to fetch materials')
    }
    return await this.parseResponse(response)
  },
  
  async downloadMaterial(materialId) {
    const response = await fetch(`${API_BASE_URL}/student/materials/${materialId}/download/`, {
      headers: getHeaders(),
    })
    
    if (!response.ok) {
      throw new Error('Download failed')
    }
    
    const blob = await response.blob()
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = response.headers.get('Content-Disposition')?.split('filename=')[1] || 'material'
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
  },
  
  // Admin APIs
  async getStudents(filters = {}) {
    const params = new URLSearchParams(filters)
    const response = await fetch(`${API_BASE_URL}/admin/students/?${params}`, {
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to fetch students')
    }
    return await this.parseResponse(response)
  },
  
  async createStudent(studentData) {
    const response = await fetch(`${API_BASE_URL}/admin/students/`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(studentData),
    })
    return await response.json()
  },
  
  async createYear(yearData) {
    const response = await fetch(`${API_BASE_URL}/admin/academic-structure/create_year/`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(yearData),
    })
    return await response.json()
  },
  
  async createSemester(semesterData) {
    const response = await fetch(`${API_BASE_URL}/admin/academic-structure/create_semester/`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(semesterData),
    })
    return await response.json()
  },
  
  async createSubject(subjectData) {
    const response = await fetch(`${API_BASE_URL}/admin/academic-structure/create_subject/`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(subjectData),
    })
    return await response.json()
  },
  
  async uploadMaterial(formData) {
    const token = getAuthToken()
    const response = await fetch(`${API_BASE_URL}/admin/materials/`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        // Don't set Content-Type for FormData, browser will set it with boundary
      },
      body: formData,
    })
    
    if (!response.ok) {
      const error = await this.parseResponse(response)
      throw new Error(error.error || error.detail || 'Upload failed')
    }
    
    return await this.parseResponse(response)
  },
  
  // Admin APIs - Get materials with filters
  async getAdminMaterials(filters = {}) {
    const params = new URLSearchParams(filters)
    const response = await fetch(`${API_BASE_URL}/admin/materials/?${params}`, {
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to fetch materials')
    }
    return await this.parseResponse(response)
  },
  
  async deleteMaterial(materialId) {
    const response = await fetch(`${API_BASE_URL}/admin/materials/${materialId}/`, {
      method: 'DELETE',
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to delete material')
    }
    return true
  },
  
  async downloadAdminMaterial(materialId) {
    const response = await fetch(`${API_BASE_URL}/admin/materials/${materialId}/download/`, {
      headers: getHeaders(),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      throw new Error('Download failed')
    }
    
    const blob = await response.blob()
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = response.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || 'material'
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
  },
  
  async deleteStudent(studentId) {
    const response = await fetch(`${API_BASE_URL}/admin/students/${studentId}/`, {
      method: 'DELETE',
      headers: getHeaders(),
    })
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login again.')
      }
      const error = await this.parseResponse(response)
      throw new Error(error.detail || error.error || 'Failed to delete student')
    }
    return true
  },
}

