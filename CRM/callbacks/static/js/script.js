document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.btn-logout').forEach(btn => {
    btn.addEventListener('click', () => {
      window.location.href = 'login.html';
    });
  });

  document.querySelectorAll('.btn-action.view-dashboard').forEach(btn => {
    btn.style.cursor = 'pointer';
    btn.addEventListener('click', () => {
      const managerEmail = btn.getAttribute('data-manager');
      if (managerEmail) {
        window.location.href = `Manager Dashboard.html?manager=${encodeURIComponent(managerEmail)}`;
      }
    });
  });

  const navLinks = document.querySelectorAll('.sidebar nav a, .sidebar nav button');
  navLinks.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      let targetSectionId = '';
      if (link.tagName.toLowerCase() === 'a') {
        targetSectionId = link.getAttribute('href').substring(1);
      } else if (link.tagName.toLowerCase() === 'button') {
        targetSectionId = link.dataset.section;
      }
      if (!targetSectionId) return;
      const mainContent = document.querySelector('.main-content');
      const sections = mainContent.querySelectorAll('section');
      sections.forEach(section => section.style.display = 'none');
      const targetSection = document.getElementById(targetSectionId);
      if (targetSection) targetSection.style.display = 'block';
      navLinks.forEach(nav => nav.classList.remove('active'));
      link.classList.add('active');
    });
  });

  const activeLink = document.querySelector('.sidebar nav a.active, .sidebar nav button.active');
  if (activeLink) {
    let initialSectionId = '';
    if (activeLink.tagName.toLowerCase() === 'a') {
      initialSectionId = activeLink.getAttribute('href').substring(1);
    } else if (activeLink.tagName.toLowerCase() === 'button') {
      initialSectionId = activeLink.dataset.section;
    }
    if (initialSectionId) {
      document.querySelectorAll('.main-content section').forEach(section => {
        section.style.display = 'none';
      });
      const initSection = document.getElementById(initialSectionId);
      if (initSection) initSection.style.display = 'block';
    }
  }

  document.querySelectorAll('.view-callbacks').forEach(btn => {
    btn.addEventListener('click', () => {
      const user = btn.dataset.user;
      if (user) {
        window.location.href = `View User Callbacks.html?user=${encodeURIComponent(user)}`;
      }
    });
  });

  document.querySelectorAll('.view-dashboard').forEach(btn => {
    btn.addEventListener('click', () => {
      const manager = btn.dataset.manager;
      if (manager) {
        window.location.href = `Manager Dashboard.html?manager=${encodeURIComponent(manager)}`;
      }
    });
  });

  document.getElementById('logoutBtn')?.addEventListener('click', () => {
    window.location.href = 'login.html';
  });
});

function showSection(sectionId) {
  document.querySelectorAll('.content-section').forEach(sec => sec.classList.remove('active'));
  document.getElementById(sectionId).classList.add('active');
  document.querySelectorAll('.sidebar nav a').forEach(link => link.classList.remove('active'));
  if (sectionId === 'profile') {
    document.getElementById('navProfile')?.classList.add('active');
  } else if (sectionId === 'appointments') {
    document.getElementById('navAppointments')?.classList.add('active');
  } else {
    document.getElementById('navCallbacks')?.classList.add('active');
  }
}

function showBooking(id) {
  document.querySelectorAll('.booking-section').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  document.getElementById('btnUpcoming')?.classList.toggle('active', id === 'upcoming');
  document.getElementById('btnHistory')?.classList.toggle('active', id === 'history');
}