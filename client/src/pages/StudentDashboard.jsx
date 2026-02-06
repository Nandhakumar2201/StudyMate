import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'

function StudentDashboard() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [departments, setDepartments] = useState([])
  const [years, setYears] = useState([])
  const [semesters, setSemesters] = useState([])
  const [subjects, setSubjects] = useState([])
  const [materials, setMaterials] = useState([])
  
  // Filter states
  const [selectedDepartment, setSelectedDepartment] = useState('')
  const [selectedYear, setSelectedYear] = useState('')
  const [selectedSemester, setSelectedSemester] = useState('')
  const [selectedSubject, setSelectedSubject] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const isAuthenticated = localStorage.getItem('isAuthenticated')
    const userRole = localStorage.getItem('userRole')
    const storedUsername = localStorage.getItem('username')

    if (!isAuthenticated || userRole !== 'student') {
      navigate('/login')
    } else {
      setUsername(storedUsername || 'Student')
      loadInitialData()
    }
  }, [navigate])

  const loadInitialData = async () => {
    try {
      const [deptsData, yearsData] = await Promise.all([
        api.getDepartments(),
        api.getYears()
      ])
      const depts = Array.isArray(deptsData.results) ? deptsData.results : (Array.isArray(deptsData) ? deptsData : [])
      const yrs = Array.isArray(yearsData.results) ? yearsData.results : (Array.isArray(yearsData) ? yearsData : [])
      setDepartments(depts)
      setYears(yrs)
      // Default to first department and first year so dropdowns show options by default
      if (depts.length > 0 && yrs.length > 0) {
        setSelectedDepartment(String(depts[0].id))
        setSelectedYear(String(yrs[0].id))
      }
    } catch (error) {
      console.error('Error loading initial data:', error)
      setDepartments([])
      setYears([])
    }
  }

  const handleDepartmentChange = async (deptId) => {
    setSelectedDepartment(deptId)
    setSelectedSemester('')
    setSelectedSubject('')
    setSemesters([])
    setSubjects([])
    
    if (deptId && selectedYear) {
      loadSemesters(deptId, selectedYear)
    }
    
    // Load materials with updated filter
    loadMaterials()
  }

  const handleYearChange = async (yearId) => {
    setSelectedYear(yearId)
    setSelectedSemester('')
    setSelectedSubject('')
    setSemesters([])
    setSubjects([])
    
    if (yearId && selectedDepartment) {
      loadSemesters(selectedDepartment, yearId)
    }
    
    // Load materials with updated filter
    loadMaterials()
  }

  const loadSemesters = async (deptId, yearId) => {
    try {
      const data = await api.getSemesters({ department: deptId, year: yearId })
      const list = Array.isArray(data.results) ? data.results : (Array.isArray(data) ? data : [])
      setSemesters(list)
      if (list.length > 0 && !selectedSemester) {
        setSelectedSemester(String(list[0].id))
      }
    } catch (error) {
      console.error('Error loading semesters:', error)
    }
  }

  const handleSemesterChange = async (semesterId) => {
    setSelectedSemester(semesterId)
    setSelectedSubject('')
    
    if (semesterId) {
      loadSubjects(semesterId)
    }
    
    // Load materials with updated filter
    loadMaterials()
  }

  const loadSubjects = async (semesterId) => {
    try {
      const data = await api.getSubjects({ semester: semesterId })
      const list = Array.isArray(data.results) ? data.results : (Array.isArray(data) ? data : [])
      setSubjects(list)
      if (list.length > 0 && !selectedSubject) {
        setSelectedSubject(String(list[0].id))
      }
    } catch (error) {
      console.error('Error loading subjects:', error)
    }
  }

  const handleSubjectChange = async (subjectId) => {
    setSelectedSubject(subjectId)
    // Load materials with updated filter (works even if subjectId is empty)
    loadMaterials()
  }

  const loadMaterials = async () => {
    setLoading(true)
    try {
      const filters = {}
      if (selectedDepartment) filters.department = selectedDepartment
      if (selectedYear) filters.year = selectedYear
      if (selectedSemester) filters.semester = selectedSemester
      if (selectedSubject) filters.subject = selectedSubject
      if (searchTerm) filters.search = searchTerm
      
      const data = await api.getMaterials(filters)
      setMaterials(data.results || data)
    } catch (error) {
      console.error('Error loading materials:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSearch = (e) => {
    e.preventDefault()
    loadMaterials()
  }

  const handleDownload = async (materialId) => {
    try {
      await api.downloadMaterial(materialId)
    } catch (error) {
      alert('Failed to download material')
    }
  }

  const handleLogout = () => {
    localStorage.removeItem('isAuthenticated')
    localStorage.removeItem('userRole')
    localStorage.removeItem('username')
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    navigate('/')
  }

  // Auto-load semesters when both department and year are selected
  useEffect(() => {
    if (selectedDepartment && selectedYear) {
      loadSemesters(selectedDepartment, selectedYear)
    }
  }, [selectedDepartment, selectedYear])

  // Auto-load subjects when semester is selected
  useEffect(() => {
    if (selectedSemester) {
      loadSubjects(selectedSemester)
    }
  }, [selectedSemester])

  // Auto-load materials when any filter changes
  useEffect(() => {
    // Load materials whenever any filter changes (including when cleared to show all)
    loadMaterials()
  }, [selectedDepartment, selectedYear, selectedSemester, selectedSubject, searchTerm])

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-2">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                StudyMate
              </h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700 font-medium">Welcome, {username}</span>
              <button
                onClick={handleLogout}
                className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-gray-900 mb-2">Student Dashboard</h2>
          <p className="text-gray-600">Browse and download study materials</p>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-xl shadow-lg p-6 mb-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Filters</h3>
          <div className="grid md:grid-cols-5 gap-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Department</label>
              <select
                value={selectedDepartment}
                onChange={(e) => handleDepartmentChange(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
              >
                <option value="">All Departments</option>
                {departments.map((dept) => (
                  <option key={dept.id} value={dept.id}>{dept.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Year</label>
              <select
                value={selectedYear}
                onChange={(e) => handleYearChange(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
              >
                <option value="">All Years</option>
                {years.map((year) => (
                  <option key={year.id} value={year.id}>{year.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Semester</label>
              <select
                value={selectedSemester}
                onChange={(e) => handleSemesterChange(e.target.value)}
                disabled={!selectedDepartment || !selectedYear}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none disabled:bg-gray-100"
              >
                <option value="">All Semesters</option>
                {semesters.map((sem) => (
                  <option key={sem.id} value={sem.id}>Semester {sem.number}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Subject</label>
              <select
                value={selectedSubject}
                onChange={(e) => handleSubjectChange(e.target.value)}
                disabled={!selectedSemester}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none disabled:bg-gray-100"
              >
                <option value="">All Subjects</option>
                {subjects.map((subject) => (
                  <option key={subject.id} value={subject.id}>{subject.name}</option>
                ))}
              </select>
            </div>

            <div className="md:col-span-1">
              <label className="block text-sm font-semibold text-gray-700 mb-2">Search</label>
              <form onSubmit={handleSearch} className="flex gap-2">
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search materials..."
                  className="flex-1 min-w-0 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
                />
                <button
                  type="submit"
                  className="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-2 rounded-lg font-medium transition-colors whitespace-nowrap flex-shrink-0"
                >
                  Search
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* Materials List */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Study Materials</h3>
          
          {loading ? (
            <div className="text-center py-8">
              <div className="text-gray-500">Loading materials...</div>
            </div>
          ) : materials.length === 0 ? (
            <div className="text-center py-8">
              <div className="text-gray-500">No materials found. Use filters to find materials.</div>
            </div>
          ) : (
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {materials.map((material) => (
                <div key={material.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-semibold text-gray-900">{material.title}</h4>
                    <span className="px-2 py-1 bg-indigo-100 text-indigo-700 text-xs rounded">
                      {material.material_type}
                    </span>
                  </div>
                  {material.description && (
                    <p className="text-sm text-gray-600 mb-3 line-clamp-2">{material.description}</p>
                  )}
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-500">{material.subject_name}</span>
                    <button
                      onClick={() => handleDownload(material.id)}
                      className="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1 rounded text-sm font-medium transition-colors"
                    >
                      Download
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default StudentDashboard
