import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ImageWithBasePath from "../../../core/common/imageWithBasePath";
import { all_routes } from "../../router/all_routes";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import ReactApexChart from "react-apexcharts";
import CircleProgressSmall from "./circleProgressSmall";
import CircleProgress from "./circleProgress";
import { Calendar } from "primereact/calendar";
import { DatePicker } from "antd";
import CommonSelect from "../../../core/common/commonSelect";
import CollapseHeader from "../../../core/common/collapse-header/collapse-header";
import { useAuth, useUser } from "@clerk/clerk-react";
import { attendance } from "../../../core/common/selectoption/selectoption";
import io from "socket.io-client";
import { ApexOptions } from "apexcharts";
import RequestModals from "../../../core/modals/requestModal";
import CryptoJS from "crypto-js";
import { DateTime } from "luxon";
import { current } from "immer";
import jsPDF from "jspdf";
import * as XLSX from "xlsx";

interface DashboardData {
  employeeDetails?: {
    _id: string;
    name: string;
    designation: string;
    role: string;
    avatar: string;
    phoneNumber: string;
    email: string;
    reportOffice: string;
    joinedOn: string;
    timeZone: string;
  };
  attendanceStats?: {
    absent: number;
    late: number;
    onTime: number;
    workFromHome: number;
    workedDays: number;
    workingDays: number;
  };

  leaveStats?: {
    lossOfPay: number;
    requestedLeaves: number;
    sickLeaves: number;
    takenLeaves: number;
    totalLeavesAllowed: number;
  };
  workingHoursStats?: {
    today?: {
      expectedHours?: number;
      workedHours?: number;
      breakHours?: number;
      overtimeRequestStatus?: string;
      expectedOvertimeHours?: number;
      overtimeHours?: number;
      punchIn?: string;
    };
    thisWeek?: {
      expectedHours: number;
      workedHours: number;
    };
    thisMonth?: {
      expectedHours: number;
      workedHours: number;
      expectedOvertimeHours: number;
      overtimeHours: number;
    };
  };
  projects?: Array<{
    projectId: string;
    projectTitle: string;
    dueDate: string;
    totalTasks: number;
    completedTasks: number;
    projectLeadAvatar: string | null;
    leadName: string | null;
    membersAvatars: string[];
  }>;
  tasks?: Array<{
    _id: string;
    title: string;
    starred: boolean;
    checked: boolean;
    status: string;
    avatars: Array<{ _id: string; avatar: string }>;
  }>;
  skills?: Array<{
    name: string;
    updatedAt: string;
    proficiency: number;
  }>;
  teamMembers?: Array<{
    _id: string;
    name: string;
    avatar: string;
    role: string;
  }>;
  notifications?: Array<{
    _id: string;
    title: string;
    createdAt: string;
    avatar: string;
  }>;
  meetings?: Array<{
    _id: string;
    title: string;
    description: string;
    startTime: string;
    tag: string;
  }>;
  performance?: {
    months: string[];
    salaries: number[];
  };
  birthdays?: Array<{
    _id: string;
    name: string;
    avatarUrl?: string;
    role?: string;
  }>;
}

const ENCRYPTION_KEY = "your-strong-encryption-key";
const leaveType = [
  { value: "Select", label: "Select" },
  { value: "Sick Leave", label: "Medical Leave" },
  { value: "Casual Leave", label: "Casual Leave" },
  { label: "Loss of Pay", value: "lossOfPay" },
];
const EmployeeDashboard = () => {
  const routes = all_routes;
  const { getToken } = useAuth();
  const [socket, setSocket] = useState<any>(null);
  const [dashboardData, setDashboardData] = useState<DashboardData>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [year, setYear] = useState(new Date().getFullYear());
  const [isPunchIn, setIsPunchIn] = useState(false);
  const [isOnBreak, setIsOnBreak] = useState(false);
  const [checkInTime, setCheckInTime] = useState<string | null>(null);
  const [breakDetails, setBreakDetails] = useState<
    { breakStartTime: string; breakEndTime: string }[]
  >([]);
  const [punchInError, setPunchInError] = useState<string | null>(null);
  const [punchOutError, setPunchOutError] = useState<string | null>(null);
  const [endBreakError, setEndBreakError] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState(() =>
    DateTime.now().setZone(dashboardData?.employeeDetails?.timeZone)
  );
  const [punchOutInitiated, setPunchOutInitiated] = useState(false);
  const [isPunchingOut, setIsPunchingOut] = useState(false);

  const [filters, setFilters] = useState({
    attendanceStats: year,
    projects: "ongoing",
    tasks: "ongoing",
    performance: year,
    skills: year,
    meetings: "today",
  });

  const currentYear = new Date().getFullYear();
  const yearOptions = Array.from({ length: 3 }, (_, i) => currentYear - i);

  const handleYearChangeAll = (year: number) => {
    console.log(`[YEAR FILTER] Year changed to: ${year}`);
    setYear(year);
    if (socket) {
      socket.emit("employee/dashboard/get-all-data", { year });
    } else {
      console.log("socket not found");
    }
  };

  // export function
  const exportToPDF = () => {
    try {
      const doc = new jsPDF();
      const currentDate = new Date().toLocaleDateString();
      const currentYear = new Date().getFullYear();

      // Title
      doc.setFontSize(20);
      doc.text("Employee Dashboard Report", 20, 20);

      doc.setFontSize(12);
      doc.text(`Generated on: ${currentDate}`, 20, 35);
      doc.text(`Year: ${currentYear}`, 20, 45);

      let yPosition = 60;

      // Employee Details
      doc.setFontSize(16);
      doc.text("Personal Information", 20, yPosition);
      yPosition += 15;

      doc.setFontSize(10);
      const employee = dashboardData.employeeDetails;
      if (employee) {
        doc.text(`Name: ${employee.name}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Designation: ${employee.designation}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Email: ${employee.email}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Phone: ${employee.phoneNumber}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Report Office: ${employee.reportOffice}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Joined On: ${employee.joinedOn}`, 20, yPosition);
        yPosition += 15;
      }

      // Attendance Stats
      doc.setFontSize(16);
      doc.text("Attendance Statistics", 20, yPosition);
      yPosition += 15;

      doc.setFontSize(10);
      const attendance = dashboardData.attendanceStats;
      if (attendance) {
        doc.text(
          `Worked Days: ${attendance.workedDays}/${attendance.workingDays}`,
          20,
          yPosition
        );
        yPosition += 8;
        doc.text(`On Time: ${attendance.onTime}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Late Arrivals: ${attendance.late}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Absent Days: ${attendance.absent}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Work From Home: ${attendance.workFromHome}`, 20, yPosition);
        yPosition += 15;
      }

      // Working Hours
      const workingHours = dashboardData.workingHoursStats;
      if (workingHours) {
        doc.setFontSize(16);
        doc.text("Working Hours", 20, yPosition);
        yPosition += 15;

        doc.setFontSize(10);
        if (workingHours.today) {
          doc.text("Today:", 20, yPosition);
          yPosition += 8;
          doc.text(
            `• Worked: ${workingHours.today.workedHours || 0}h`,
            30,
            yPosition
          );
          yPosition += 8;
          doc.text(
            `• Break: ${workingHours.today.breakHours || 0}h`,
            30,
            yPosition
          );
          yPosition += 8;
          doc.text(
            `• Overtime: ${workingHours.today.overtimeHours || 0}h`,
            30,
            yPosition
          );
          yPosition += 8;
          doc.text(
            `• Punch In: ${workingHours.today.punchIn || "N/A"}`,
            30,
            yPosition
          );
          yPosition += 15;
        }

        if (workingHours.thisWeek) {
          doc.text(
            `This Week: ${workingHours.thisWeek.workedHours}h worked / ${workingHours.thisWeek.expectedHours}h expected`,
            20,
            yPosition
          );
          yPosition += 15;
        }

        if (workingHours.thisMonth) {
          doc.text(
            `This Month: ${workingHours.thisMonth.workedHours}h worked / ${workingHours.thisMonth.expectedHours}h expected`,
            20,
            yPosition
          );
          yPosition += 8;
          doc.text(
            `Overtime: ${workingHours.thisMonth.overtimeHours || 0}h`,
            20,
            yPosition
          );
          yPosition += 15;
        }
      }

      // Leave Stats
      const leaves = dashboardData.leaveStats;
      if (leaves) {
        doc.setFontSize(16);
        doc.text("Leave Summary", 20, yPosition);
        yPosition += 15;

        doc.setFontSize(10);
        doc.text(`Total Allowed: ${leaves.totalLeavesAllowed}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Taken: ${leaves.takenLeaves}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Sick Leaves: ${leaves.sickLeaves}`, 20, yPosition);
        yPosition += 8;
        doc.text(`Loss of Pay: ${leaves.lossOfPay}`, 20, yPosition);
        yPosition += 15;
      }

      // Projects
      if (dashboardData.projects && dashboardData.projects.length > 0) {
        if (yPosition > 250) {
          doc.addPage();
          yPosition = 20;
        }

        doc.setFontSize(16);
        doc.text("Current Projects", 20, yPosition);
        yPosition += 15;

        doc.setFontSize(10);
        dashboardData.projects.forEach((project) => {
          if (yPosition > 280) {
            doc.addPage();
            yPosition = 20;
          }
          doc.text(`• ${project.projectTitle}`, 20, yPosition);
          yPosition += 8;
          doc.text(`  Due: ${project.dueDate}`, 30, yPosition);
          yPosition += 8;
          doc.text(
            `  Tasks: ${project.completedTasks}/${project.totalTasks}`,
            30,
            yPosition
          );
          yPosition += 8;
          doc.text(`  Lead: ${project.leadName || "N/A"}`, 30, yPosition);
          yPosition += 12;
        });
      }

      // Save the PDF
      doc.save(
        `employee-dashboard-${employee?.name || "report"}-${currentDate.replace(
          /\//g,
          "-"
        )}.pdf`
      );
    } catch (error) {
      console.error("Error generating PDF:", error);
      alert("Error generating PDF export. Please try again.");
    }
  };

  const exportToExcel = () => {
    try {
      const currentDate = new Date().toLocaleDateString();
      const wb = XLSX.utils.book_new();

      // Employee Details Sheet
      if (dashboardData.employeeDetails) {
        const employeeData: (string | number)[][] = [
          ["Employee Information", ""],
          ["Name", dashboardData.employeeDetails.name],
          ["Designation", dashboardData.employeeDetails.designation],
          ["Email", dashboardData.employeeDetails.email],
          ["Phone", dashboardData.employeeDetails.phoneNumber],
          ["Report Office", dashboardData.employeeDetails.reportOffice],
          ["Joined On", dashboardData.employeeDetails.joinedOn],
          ["Time Zone", dashboardData.employeeDetails.timeZone],
        ];
        const employeeWS = XLSX.utils.aoa_to_sheet(employeeData);
        XLSX.utils.book_append_sheet(wb, employeeWS, "Employee Info");
      }

      // Attendance Stats Sheet
      if (dashboardData.attendanceStats) {
        const attendanceData: (string | number)[][] = [
          ["Attendance Statistics", ""],
          [
            "Worked Days",
            `${dashboardData.attendanceStats.workedDays}/${dashboardData.attendanceStats.workingDays}`,
          ],
          ["On Time", dashboardData.attendanceStats.onTime],
          ["Late Arrivals", dashboardData.attendanceStats.late],
          ["Absent Days", dashboardData.attendanceStats.absent],
          ["Work From Home", dashboardData.attendanceStats.workFromHome],
        ];
        const attendanceWS = XLSX.utils.aoa_to_sheet(attendanceData);
        XLSX.utils.book_append_sheet(wb, attendanceWS, "Attendance");
      }

      // Working Hours Sheet
      if (dashboardData.workingHoursStats) {
        const workingHoursData: (string | number)[][] = [["Working Hours", ""]];

        if (dashboardData.workingHoursStats.today) {
          workingHoursData.push(
            ["Today's Hours", ""],
            [
              "Worked Hours",
              dashboardData.workingHoursStats.today.workedHours || 0,
            ],
            [
              "Break Hours",
              dashboardData.workingHoursStats.today.breakHours || 0,
            ],
            [
              "Overtime Hours",
              dashboardData.workingHoursStats.today.overtimeHours || 0,
            ],
            [
              "Punch In Time",
              dashboardData.workingHoursStats.today.punchIn || "N/A",
            ]
          );
        }

        if (dashboardData.workingHoursStats.thisWeek) {
          workingHoursData.push(
            ["", ""],
            ["This Week", ""],
            [
              "Worked Hours",
              dashboardData.workingHoursStats.thisWeek.workedHours,
            ],
            [
              "Expected Hours",
              dashboardData.workingHoursStats.thisWeek.expectedHours,
            ]
          );
        }

        if (dashboardData.workingHoursStats.thisMonth) {
          workingHoursData.push(
            ["", ""],
            ["This Month", ""],
            [
              "Worked Hours",
              dashboardData.workingHoursStats.thisMonth.workedHours,
            ],
            [
              "Expected Hours",
              dashboardData.workingHoursStats.thisMonth.expectedHours,
            ],
            [
              "Overtime Hours",
              dashboardData.workingHoursStats.thisMonth.overtimeHours || 0,
            ]
          );
        }

        const workingHoursWS = XLSX.utils.aoa_to_sheet(workingHoursData);
        XLSX.utils.book_append_sheet(wb, workingHoursWS, "Working Hours");
      }

      // Leave Stats Sheet
      if (dashboardData.leaveStats) {
        const leaveData: (string | number)[][] = [
          ["Leave Statistics", ""],
          ["Total Leaves Allowed", dashboardData.leaveStats.totalLeavesAllowed],
          ["Taken Leaves", dashboardData.leaveStats.takenLeaves],
          ["Sick Leaves", dashboardData.leaveStats.sickLeaves],
          ["Loss of Pay", dashboardData.leaveStats.lossOfPay],
          ["Requested Leaves", dashboardData.leaveStats.requestedLeaves],
        ];
        const leaveWS = XLSX.utils.aoa_to_sheet(leaveData);
        XLSX.utils.book_append_sheet(wb, leaveWS, "Leaves");
      }

      // Projects Sheet
      if (dashboardData.projects && dashboardData.projects.length > 0) {
        const projectData: (string | number)[][] = [
          [
            "Project Title",
            "Due Date",
            "Tasks Completed",
            "Total Tasks",
            "Lead",
          ],
        ];

        dashboardData.projects.forEach((project) => {
          projectData.push([
            project.projectTitle,
            project.dueDate,
            project.completedTasks,
            project.totalTasks,
            project.leadName || "N/A",
          ]);
        });

        const projectWS = XLSX.utils.aoa_to_sheet(projectData);
        XLSX.utils.book_append_sheet(wb, projectWS, "Projects");
      }

      // Tasks Sheet
      if (dashboardData.tasks && dashboardData.tasks.length > 0) {
        const taskData: (string | boolean)[][] = [
          ["Task Title", "Status", "Starred"],
        ];

        dashboardData.tasks.forEach((task) => {
          taskData.push([task.title, task.status, task.starred]);
        });

        const taskWS = XLSX.utils.aoa_to_sheet(taskData);
        XLSX.utils.book_append_sheet(wb, taskWS, "Tasks");
      }

      // Skills Sheet
      if (dashboardData.skills && dashboardData.skills.length > 0) {
        const skillData: (string | number)[][] = [
          ["Skill Name", "Proficiency", "Last Updated"],
        ];

        dashboardData.skills.forEach((skill) => {
          skillData.push([skill.name, skill.proficiency, skill.updatedAt]);
        });

        const skillWS = XLSX.utils.aoa_to_sheet(skillData);
        XLSX.utils.book_append_sheet(wb, skillWS, "Skills");
      }

      // Save the Excel file
      const fileName = `employee-dashboard-${
        dashboardData.employeeDetails?.name || "report"
      }-${currentDate.replace(/\//g, "-")}.xlsx`;
      XLSX.writeFile(wb, fileName);
    } catch (error) {
      console.error("Error generating Excel:", error);
      alert("Error generating Excel export. Please try again.");
    }
  };

  useEffect(() => {
    let isMounted = true;
    let currentSocket: any = null;

    const initSocket = async () => {
      try {
        console.log("Initializing socket connection...");
        const token = await getToken();
        console.log("Token obtained, creating socket...");

        if (!isMounted) return;

        currentSocket = io("http://localhost:5000", {
          auth: { token },
          timeout: 20000,
        });

        const timeoutId = setTimeout(() => {
          if (loading && isMounted) {
            console.warn("Dashboard loading timeout - showing fallback");
            setError("Dashboard loading timed out. Please refresh the page.");
            setLoading(false);
          }
        }, 30000);

        currentSocket.on("connect", () => {
          console.log("Connected to admin dashboard");
          console.log("Requesting dashboard data...");
          currentSocket.emit("employee/dashboard/get-all-data");
        });

        currentSocket.on(
          "employee/dashboard/get-all-data-response",
          (response: any) => {
            console.log("Received dashboard data response:", response);
            clearTimeout(timeoutId);
            if (!isMounted) return;
            if (response.done) {
              console.log("Dashboard data loaded successfully");
              setDashboardData(response.data);
              setLoading(false);
            } else {
              console.error("Dashboard data error:", response.error);
              setError(response.error || "Failed to fetch dashboard data");
              setLoading(false);
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/get-attendance-stats-response",
          (response: any) => {
            if (!isMounted) return;
            if (response.done) {
              console.log("Attendance data", response);
              setDashboardData((prev) => ({
                ...prev,
                attendanceStats: response.data,
              }));
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/get-leave-stats-response",
          (response: any) => {
            if (!isMounted) return;
            if (response.done) {
              setDashboardData((prev) => ({
                ...prev,
                leaveStats: response.data,
              }));
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/get-projects-response",
          (response: any) => {
            if (!isMounted) return;
            if (response.done) {
              console.log(response);
              setDashboardData((prev) => ({
                ...prev,
                projects: response.data,
              }));
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/get-tasks-response",
          (response: any) => {
            if (!isMounted) return;
            if (response.done) {
              setDashboardData((prev) => ({
                ...prev,
                tasks: response.data,
              }));
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/get-skills-response",
          (response: any) => {
            if (!isMounted) return;
            if (response.done) {
              setDashboardData((prev) => ({
                ...prev,
                skills: response.data,
              }));
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/get-meetings-response",
          (response: any) => {
            if (!isMounted) return;
            if (response.done) {
              setDashboardData((prev) => ({
                ...prev,
                meetings: response.data,
              }));
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/get-performance-response",
          (response: any) => {
            if (!isMounted) return;
            if (response.done) {
              console.log(response);
              setDashboardData((prev) => ({
                ...(prev ?? {}),
                performance: response.data,
              }));
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/punch-in-response",
          (response: {
            done: boolean;
            data?: {
              punchIn: string;
              overtimeRequestStatus?: string;
              overtimeHours?: number;
            };
            error?: string;
          }) => {
            if (!isMounted) return;

            if (response?.done) {
              setDashboardData((prev) => ({
                ...prev,
                workingHoursStats: {
                  ...prev.workingHoursStats,
                  today: {
                    ...prev.workingHoursStats?.today,
                    punchIn: response.data?.punchIn || new Date().toISOString(),
                    overtimeRequestStatus: response.data?.overtimeRequestStatus,
                    expectedOvertimeHours: response.data?.overtimeHours ?? 0,
                  },
                  thisWeek: prev.workingHoursStats?.thisWeek,
                  thisMonth: prev.workingHoursStats?.thisMonth,
                },
              }));

              setIsPunchIn(true);
              const punchInTime =
                response.data?.punchIn || new Date().toISOString();
              setCheckInTime(punchInTime);

              const breakDetails: Array<{
                breakStartTime: string;
                breakEndTime: string;
              }> = [];
              const encryptedBreaks = encryptValue(
                JSON.stringify(breakDetails)
              );
              localStorage.setItem("encryptedBreakDetails", encryptedBreaks);
              localStorage.setItem(
                "encryptedPunchInTime",
                encryptValue(punchInTime)
              );

              setBreakDetails(breakDetails);
              setPunchInError(null);
            } else {
              console.warn("[PunchIn] Failed:", response?.error);
              setPunchInError(response?.error ?? "Punch-in failed.");
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/punch-out-response",
          (response: any) => {
            console.log("Hello3");

            if (!isMounted) return;
            if (response?.done) {
              console.log("Hello2");

              localStorage.removeItem("encryptedPunchInTime");
              localStorage.removeItem("encryptedBreakDetails");
              setIsPunchIn(false);
              setCheckInTime(null);
              setBreakDetails([]);
              setIsOnBreak(false);
              setPunchOutError(null);
              currentSocket.emit("employee/dashboard/working-hours-stats");
            } else {
              console.warn("[PunchOUT] Failed:", response?.error);
              setPunchOutError(response?.error ?? "Punch-out failed.");
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/working-hours-stats-response",
          (response: any) => {
            if (!isMounted) return;

            if (response?.done) {
              console.log("Hello1");

              setDashboardData((prev) => ({
                ...prev,
                workingHoursStats: {
                  today: {
                    ...prev?.workingHoursStats?.today,
                    expectedHours: response.data.today.expectedHours,
                    workedHours: response.data.today.workedHours,
                    breakHours: response.data.today.breakHours,
                    overtimeHours: response.data.today.overtimeHours,
                  },
                  thisWeek: {
                    ...prev?.workingHoursStats?.thisWeek,
                    expectedHours: response.data.thisWeek.expectedHours,
                    workedHours: response.data.thisWeek.workedHours,
                  },
                  thisMonth: {
                    ...prev?.workingHoursStats?.thisMonth,
                    expectedHours: response.data.thisMonth.expectedHours,
                    workedHours: response.data.thisMonth.workedHours,
                    overtimeHours: response.data.thisMonth.overtimeHours,
                    expectedOvertimeHours:
                      response.data.thisMonth.expectedOvertimeHours,
                  },
                },
              }));
            } else {
              console.error(
                "Failed to load working hours stats:",
                response?.error
              );
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/start-break-response",
          (response: any) => {
            if (!isMounted) return;

            let currentBreaks: Array<{
              breakStartTime: string;
              breakEndTime: string;
            }> = [];
            try {
              const encrypted = localStorage.getItem("encryptedBreakDetails");
              if (encrypted) {
                const decryptedStr = decryptValue(encrypted);
                if (decryptedStr) {
                  currentBreaks = JSON.parse(decryptedStr);
                }
              }
            } catch (error) {
              console.error("Error reading or parsing break details:", error);
              currentBreaks = [];
            }
            if (response?.done) {
              const newBreak = {
                breakStartTime:
                  response.data?.breakStartTime || new Date().toISOString(),
                breakEndTime: "",
              };
              const updatedBreaks = [...currentBreaks, newBreak];
              setBreakDetails(updatedBreaks);
              try {
                const encryptedUpdatedBreaks = encryptValue(
                  JSON.stringify(updatedBreaks)
                );
                localStorage.setItem(
                  "encryptedBreakDetails",
                  encryptedUpdatedBreaks
                );
              } catch (error) {
                console.error(
                  "Failed to encrypt and save break details:",
                  error
                );
              }
              setIsOnBreak(true);
            } else {
              console.warn("Break start failed:", response?.error);
            }
          }
        );

        currentSocket.on(
          "employee/dashboard/end-break-response",
          (response: any) => {
            if (!isMounted) return;

            if (response?.done) {
              let breakDetails = [];
              try {
                const encrypted = localStorage.getItem("encryptedBreakDetails");
                if (encrypted) {
                  const decrypted = decryptValue(encrypted);
                  breakDetails = decrypted ? JSON.parse(decrypted) : [];
                }
              } catch (err) {
                console.error("Failed to decrypt break details", err);
                breakDetails = [];
              }
              const breakEndTime = new Date().toISOString();
              const lastBreak = breakDetails[breakDetails.length - 1];
              if (lastBreak && !lastBreak.breakEndTime) {
                lastBreak.breakEndTime = breakEndTime;
                try {
                  const encryptedUpdated = encryptValue(
                    JSON.stringify(breakDetails)
                  );
                  localStorage.setItem(
                    "encryptedBreakDetails",
                    encryptedUpdated
                  );
                } catch (err) {
                  console.error("Failed to encrypt or save break details", err);
                }
                setIsOnBreak(false);
                setBreakDetails(breakDetails);
                setEndBreakError(null);
              } else {
                console.warn("No open break session found to close.");
                setEndBreakError("No open break session found to close.");
              }
            } else {
              console.error(
                "Break end failed:",
                response?.error || "Unknown error"
              );
              setEndBreakError(response?.error ?? "Failed to end break.");
            }
          }
        );

        currentSocket.on("connect_error", (err: any) => {
          console.error("Socket connection error:", err);
          clearTimeout(timeoutId);
          if (!isMounted) return;

          setError("Failed to connect to server");
          setLoading(false);
        });

        currentSocket.on("disconnect", (reason: any) => {
          console.log("Socket disconnected:", reason);
          clearTimeout(timeoutId);
        });

        if (isMounted) {
          setSocket(currentSocket);
        }
      } catch (err) {
        console.error("Failed to initialize socket:", err);
        if (isMounted) {
          setError("Failed to authenticate");
          setLoading(false);
        }
      }
    };

    if (!socket) initSocket();

    return () => {
      isMounted = false;
      if (currentSocket) {
        console.log("Cleaning up socket connection...");
        currentSocket.removeAllListeners();
        currentSocket.disconnect();
      }
    };
  }, []);

  // helper functions
  const baseHours = dashboardData?.workingHoursStats?.today?.expectedHours ?? 8;
  const overtimeHours =
    dashboardData?.workingHoursStats?.today?.expectedOvertimeHours ?? 0;
  const expectedHours = baseHours + overtimeHours;
  const expectedSeconds = expectedHours * 3600;
  const punchInTimeUTC = checkInTime ?? null;
  const timeZone = dashboardData?.employeeDetails?.timeZone || "Asia/Kolkata";
  const [leftover, setLeftover] = useState(() =>
    getLeftoverTimeObject(punchInTimeUTC, timeZone, expectedSeconds)
  );

  function getLeftoverTimeObject(
    punchIn: string | null,
    timeZone: string,
    expectedSeconds: number
  ) {
    if (!punchIn || !timeZone) {
      return {
        c_time: "00:00:00",
        hrs: 0,
        mins: 0,
        secs: 0,
        isTimerExpired: true,
      };
    }

    const punchInDT = DateTime.fromISO(punchIn, { zone: "utc" }).setZone(
      timeZone
    );
    const now = DateTime.now().setZone(timeZone);

    let elapsed = now.diff(punchInDT, "seconds").seconds ?? 0;
    if (elapsed < 0) elapsed = 0;

    let leftover = expectedSeconds - elapsed;
    const isTimerExpired = leftover <= 0;
    if (leftover < 0) leftover = 0;

    const hrs = Math.floor(leftover / 3600);
    const mins = Math.floor((leftover % 3600) / 60);
    const secs = Math.floor(leftover % 60);
    const c_time = [hrs, mins, secs]
      .map((n) => String(n).padStart(2, "0"))
      .join(":");

    return {
      c_time,
      hrs,
      mins,
      secs,
      isTimerExpired,
    };
  }

  useEffect(() => {
    const interval = setInterval(() => {
      setLeftover(
        getLeftoverTimeObject(punchInTimeUTC ?? "", timeZone, expectedSeconds)
      );
    }, 1000);
    return () => clearInterval(interval);
  }, [punchInTimeUTC, timeZone, expectedSeconds]);

  useEffect(() => {
    if (!punchInTimeUTC || leftover.isTimerExpired) return;

    const interval = setInterval(() => {
      const newLeftover = getLeftoverTimeObject(
        punchInTimeUTC,
        timeZone,
        expectedSeconds
      );
      setLeftover(newLeftover);

      if (newLeftover.c_time === "00:00:00" && !punchOutInitiated) {
        console.log("Auto punch-out triggered");
        handlePunchOut();
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [punchInTimeUTC, leftover.isTimerExpired, punchOutInitiated]);

  const calculateElapsedTime = (punchInISO: string) => {
    const now = DateTime.now();
    const punchIn = DateTime.fromISO(punchInISO);
    const diff = now.diff(punchIn, ["hours", "minutes", "seconds"]);

    return {
      c_time: `${diff.hours}h ${diff.minutes}m`,
      hrs: diff.hours,
      mins: diff.minutes,
      secs: Math.floor(diff.seconds),
    };
  };

  const [elapsedTime, setElapsedTime] = useState(
    calculateElapsedTime(checkInTime!)
  );

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedTime(calculateElapsedTime(checkInTime!));
    }, 60000);
    return () => clearInterval(timer);
  }, [checkInTime]);

  useEffect(() => {
    const encryptedPunchInTime = localStorage.getItem("encryptedPunchInTime");
    if (encryptedPunchInTime) {
      try {
        const decryptedPunchInTime = decryptValue(encryptedPunchInTime);
        setCheckInTime(decryptedPunchInTime);
        setIsPunchIn(true);
      } catch (e) {
        console.error("Failed to decrypt punch-in time", e);
        if (dashboardData?.workingHoursStats?.today?.punchIn) {
          setCheckInTime(dashboardData.workingHoursStats.today.punchIn);
          setIsPunchIn(true);
        }
      }
    } else if (dashboardData?.workingHoursStats?.today?.punchIn) {
      setCheckInTime(dashboardData.workingHoursStats.today.punchIn);
      setIsPunchIn(true);
    }
  }, [dashboardData]);

  function encryptValue(value: string): string {
    return CryptoJS.AES.encrypt(value, ENCRYPTION_KEY).toString();
  }

  function decryptValue(encrypted: string): string | null {
    try {
      const bytes = CryptoJS.AES.decrypt(encrypted, ENCRYPTION_KEY);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      return decrypted;
    } catch {
      return null;
    }
  }
  function convertUtcToTimeZone(
    utcDate: string | Date,
    timeZone: string,
    format = "HH:mm:ss"
  ): string {
    return DateTime.fromISO(
      typeof utcDate === "string" ? utcDate : utcDate.toISOString(),
      { zone: "utc" }
    )
      .setZone(timeZone)
      .toFormat(format);
  }

  function handlePunchIn(
    socket: any,
    setPunchInError: (v: string | null) => void
  ) {
    console.log("[PunchIn] Called");
    if (!socket || !socket.connected) {
      console.error("Socket not connected");
      setPunchInError("Unable to connect to server.");
      return;
    }
    socket.emit("employee/dashboard/punch-in");
  }

  let time;
  const encTime = localStorage.getItem("encryptedPunchInTime");
  if (encTime) {
    time = decryptValue(encTime);
  }

  function handleBreakStart(socket: any) {
    if (!socket || !socket.connected) {
      console.error("Socket not connected");
      return;
    }
    socket.emit("employee/dashboard/start-break");
  }

  function handleEndBreak(
    socket: any,
    setEndBreakError: (v: string | null) => void
  ) {
    console.log("[EndBreak] Called");
    if (!socket || !socket.connected) {
      console.error("Socket not connected");
      setEndBreakError("Unable to connect to server.");
      return;
    }
    socket.emit("employee/dashboard/end-break");
  }

  const handlePunchOut = async () => {
    if (punchOutInitiated || isPunchingOut) return;
    setIsPunchingOut(true);
    try {
      setPunchOutInitiated(true);
      socket.emit("employee/dashboard/punch-out");
    } catch (error) {
      console.error("Punch-out error:", error);
      setPunchOutInitiated(false);
    } finally {
      setIsPunchingOut(false);
    }
  };

  function pad(value: number): string {
    return value.toString().padStart(2, "0");
  }

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case "completed":
        return "badge-soft-success";
      case "pending":
        return "badge-secondary-transparent";
      case "inprogress":
        return "bg-transparent-purple";
      case "onhold":
        return "bg-soft-pink";
      default:
        return "bg-light";
    }
  };

  function formatDateProject(dateString: string): string {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return "Invalid date";
    const day = String(date.getDate()).padStart(2, "0");
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
  }

  function convertHoursDecimalToHoursMinutes(decimalHours: number): string {
    if (decimalHours === undefined || decimalHours === null) return "0h 0m";
    const totalMinutes = Math.round(decimalHours * 60);
    const hours = Math.floor(totalMinutes / 60);
    const minutes = totalMinutes % 60;
    return `${hours}h ${minutes}m`;
  }
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(
        DateTime.now().setZone(dashboardData?.employeeDetails?.timeZone)
      );
    }, 1000);
    return () => clearInterval(timer);
  }, [dashboardData?.employeeDetails?.timeZone]);

  const formattedMins = currentTime.toFormat("h:mm a, dd LLL yyyy");
  const formattedSec = currentTime.toFormat("h:mm:ss");

  function parseHourDecimal(hourDecimal: number | undefined): number {
    if (hourDecimal == null) return 0;
    const hours = Math.floor(hourDecimal);
    const minutes = Math.round((hourDecimal - hours) * 100);
    return hours + minutes / 60;
  }

  function calculateTimePercentages(
    totalWorkingHours?: number,
    productiveHours?: number,
    overtimeHours?: number,
    breakTime?: number
  ) {
    const total = parseHourDecimal(totalWorkingHours);
    const productive = parseHourDecimal(productiveHours);
    const overtime = parseHourDecimal(overtimeHours);
    const brk = parseHourDecimal(breakTime);

    if (total === 0) {
      return {
        productivePercent: 0,
        overtimePercent: 0,
        breakPercent: 0,
      };
    }

    return {
      productivePercent: (productive / total) * 100,
      overtimePercent: (overtime / total) * 100,
      breakPercent: (brk / total) * 100,
    };
  }

  //New Chart
  const leavesChart_series = [
    dashboardData?.attendanceStats?.onTime || 0,
    dashboardData?.attendanceStats?.late || 0,
    dashboardData?.attendanceStats?.workFromHome || 0,
    dashboardData?.attendanceStats?.absent || 0,
    dashboardData?.leaveStats?.sickLeaves || 0,
  ];
  const leavesChart_options: ApexOptions = {
    chart: {
      height: 165,
      type: "donut",
      toolbar: { show: false },
    },
    labels: ["On Time", "Late", "Work From Home", "Absent", "Sick Leaves"],
    plotOptions: {
      bar: {
        horizontal: false,
        columnWidth: "50%",
      },
    },
    dataLabels: { enabled: false },
    series: [
      dashboardData?.attendanceStats?.onTime || 0,
      dashboardData?.attendanceStats?.late || 0,
      dashboardData?.attendanceStats?.workFromHome || 0,
      dashboardData?.attendanceStats?.absent || 0,
      dashboardData?.leaveStats?.sickLeaves || 0,
    ],
    colors: ["#0C4B5E", "#03C95A", "#F26522", "#E70D0D", "#FFC107"],
    responsive: [
      {
        breakpoint: 480,
        options: {
          chart: { width: 200 },
          legend: { show: false },
        },
      },
    ],
    legend: { show: false },
  };

  const performance_chart2_series = dashboardData?.performance?.salaries ?? [];
  const months = dashboardData?.performance?.months ?? [];

  const performance_chart2_options: ApexOptions = {
    chart: {
      height: 288,
      type: "area",
      zoom: {
        enabled: false,
      },
    },
    colors: ["#00C853"],
    dataLabels: {
      enabled: false,
    },
    stroke: {
      curve: "straight",
    },
    title: {
      text: "",
      align: "left",
    },
    xaxis: {
      categories: months,
    },
    yaxis: {},
    legend: {
      position: "top",
    },
  };

  const handleMeetingFilterChange = (filter: "today" | "month" | "year") => {
    setFilters((prev) => ({ ...prev, meetings: filter }));
    socket.emit("employee/dashboard/get-meetings", { filter: filter });
  };

  const handleProjectFilterChange = (filter: "all" | "ongoing") => {
    setFilters((prev) => ({ ...prev, projects: filter }));
    socket.emit("employee/dashboard/get-projects", { filter: filter });
  };

  const handleTaskChange = (filter: "all" | "ongoing") => {
    setFilters((prev) => ({ ...prev, tasks: filter }));
    socket.emit("employee/dashboard/get-tasks", { filter: filter });
  };
  const handleYearChange = (widget: string, year: number) => {
    console.log(`[YEAR FILTER] ${widget}: ${year}`);
    setFilters((prev) => ({
      ...prev,
      [widget]: year,
    }));
    if (socket) {
      const payload = { year: Number(year) };
      if (widget === "attendanceStats") {
        console.log("[SOCKET EMIT] Payload:", payload);
        socket.emit("employee/dashboard/get-attendance-stats", payload);
        socket.emit("employee/dashboard/get-leave-stats", payload);
      }
      if (widget === "performance") {
        socket.emit("employee/dashboard/get-performance", payload);
      }
      if (widget === "skills") {
        socket.emit("employee/dashboard/get-skills", payload);
      }
    }
  };
  return (
    <>
      {/* Page Wrapper */}
      <div className="page-wrapper">
        <div className="content">
          {/* Breadcrumb */}
          <div className="d-md-flex d-block align-items-center justify-content-between page-breadcrumb mb-3">
            <div className="my-auto mb-2">
              <h2 className="mb-1">Employee Dashboard</h2>
              <nav>
                <ol className="breadcrumb mb-0">
                  <li className="breadcrumb-item">
                    <Link to={routes.adminDashboard}>
                      <i className="ti ti-smart-home" />
                    </Link>
                  </li>
                  <li className="breadcrumb-item">Dashboard</li>
                  <li className="breadcrumb-item active" aria-current="page">
                    Employee Dashboard
                  </li>
                </ol>
              </nav>
            </div>
            <div className="d-flex my-xl-auto right-content align-items-center flex-wrap ">
              <div className="me-2 mb-2">
                <div className="dropdown">
                  <Link
                    to="#"
                    className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                  >
                    <i className="ti ti-file-export me-1" />
                    Export
                  </Link>
                  <ul className="dropdown-menu  dropdown-menu-end p-3">
                    <li>
                      <Link
                        to="#"
                        className="dropdown-item rounded-1"
                        onClick={(e) => {
                          e.preventDefault();
                          exportToPDF();
                        }}
                      >
                        <i className="ti ti-file-type-pdf me-1" />
                        Export as PDF
                      </Link>
                    </li>
                    <li>
                      <Link
                        to="#"
                        className="dropdown-item rounded-1"
                        onClick={(e) => {
                          e.preventDefault();
                          exportToExcel();
                        }}
                      >
                        <i className="ti ti-file-type-xls me-1" />
                        Export as Excel{" "}
                      </Link>
                    </li>
                  </ul>
                </div>
              </div>
              <div className="me-2 mb-2">
                <div className="dropdown">
                  <Link
                    to="#"
                    className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                    role="button"
                    aria-expanded="false"
                  >
                    <i className="ti ti-calendar me-1" />
                    {year}
                  </Link>
                  <ul className="dropdown-menu dropdown-menu-end p-3">
                    {yearOptions.map((year) => (
                      <li key={year}>
                        <Link
                          to="#"
                          className="dropdown-item rounded-1"
                          onClick={() => handleYearChangeAll(year)}
                        >
                          {year}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="ms-2 head-icons">
                <CollapseHeader />
              </div>
            </div>
          </div>
          <div className="row">
            <div className="col-xl-4 d-flex">
              <div className="card position-relative flex-fill">
                <div className="card-header bg-dark">
                  <div className="d-flex align-items-center">
                    <span className="avatar avatar-lg avatar-rounded border border-white border-2 flex-shrink-0 me-2">
                      <ImageWithBasePath
                        src={
                          dashboardData?.employeeDetails?.avatar ||
                          "assets/img/users/user-01.jpg"
                        }
                        alt="Img"
                      />
                    </span>
                    <div>
                      <h5 className="text-white mb-1">
                        {dashboardData?.employeeDetails?.name}
                      </h5>
                      <div className="d-flex align-items-center">
                        <p className="text-white fs-12 mb-0">
                          {dashboardData?.employeeDetails?.designation}
                        </p>
                        <span className="mx-1">
                          <i className="ti ti-point-filled text-primary" />
                        </span>
                        <p className="fs-12">
                          {dashboardData?.employeeDetails?.role}
                        </p>
                      </div>
                    </div>
                  </div>
                  <Link
                    to="#"
                    className="btn btn-icon btn-sm text-white rounded-circle edit-top"
                  >
                    <i className="ti ti-edit" />
                  </Link>
                </div>
                <div className="card-body">
                  <div className="mb-3">
                    <span className="d-block mb-1 fs-13">Phone Number</span>
                    <p className="text-gray-9">
                      {dashboardData?.employeeDetails?.phoneNumber}
                    </p>
                  </div>
                  <div className="mb-3">
                    <span className="d-block mb-1 fs-13">Email Address</span>
                    <p className="text-gray-9">
                      {dashboardData?.employeeDetails?.email}
                    </p>
                  </div>
                  <div className="mb-3">
                    <span className="d-block mb-1 fs-13">Report Office</span>
                    <p className="text-gray-9">
                      {dashboardData?.employeeDetails?.reportOffice}
                    </p>
                  </div>
                  <div>
                    <span className="d-block mb-1 fs-13">Joined on</span>
                    <p className="text-gray-9">
                      {dashboardData?.employeeDetails?.joinedOn}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-5 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap row-gap-2">
                    <h5>Leave Details</h5>
                    <div className="dropdown">
                      <Link
                        to="#"
                        className="btn btn-white border btn-sm d-inline-flex align-items-center"
                        data-bs-toggle="dropdown"
                      >
                        <i className="ti ti-calendar me-1" />
                        {filters.attendanceStats}
                      </Link>
                      <ul className="dropdown-menu dropdown-menu-end p-3">
                        {yearOptions.map((year) => (
                          <li key={year}>
                            <Link
                              to="#"
                              className="dropdown-item rounded-1"
                              onClick={() =>
                                handleYearChange("attendanceStats", year)
                              }
                            >
                              {year}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  <div className="row align-items-center">
                    <div className="col-md-6">
                      <div className="mb-4">
                        <div className="mb-3">
                          <p className="d-flex align-items-center">
                            <i className="ti ti-circle-filled fs-8 text-dark me-1" />
                            <span className="text-gray-9 fw-semibold me-1">
                              {dashboardData?.attendanceStats?.onTime}
                            </span>
                            on time
                          </p>
                        </div>
                        <div className="mb-3">
                          <p className="d-flex align-items-center">
                            <i className="ti ti-circle-filled fs-8 text-success me-1" />
                            <span className="text-gray-9 fw-semibold me-1">
                              {dashboardData?.attendanceStats?.late}
                            </span>
                            Late Attendance
                          </p>
                        </div>
                        <div className="mb-3">
                          <p className="d-flex align-items-center">
                            <i className="ti ti-circle-filled fs-8 text-primary me-1" />
                            <span className="text-gray-9 fw-semibold me-1">
                              {dashboardData?.attendanceStats?.workFromHome}
                            </span>
                            Work From Home
                          </p>
                        </div>
                        <div className="mb-3">
                          <p className="d-flex align-items-center">
                            <i className="ti ti-circle-filled fs-8 text-danger me-1" />
                            <span className="text-gray-9 fw-semibold me-1">
                              {dashboardData?.attendanceStats?.absent}
                            </span>
                            Absent
                          </p>
                        </div>
                        <div>
                          <p className="d-flex align-items-center">
                            <i className="ti ti-circle-filled fs-8 text-warning me-1" />
                            <span className="text-gray-9 fw-semibold me-1">
                              {dashboardData?.leaveStats?.sickLeaves}
                            </span>
                            Sick Leave
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div
                        className="d-flex justify-content-md-end"
                        style={{ width: "100%" }}
                      >
                        <div style={{ width: 200, height: 165 }}>
                          <ReactApexChart
                            id="leaves_chart"
                            options={leavesChart_options}
                            series={leavesChart_series}
                            type="donut"
                            height={165}
                            width={200}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap row-gap-2">
                    <h5>Leave Details</h5>
                    <div className="dropdown">
                      <Link
                        to="#"
                        className="btn btn-white border btn-sm d-inline-flex align-items-center"
                        data-bs-toggle="dropdown"
                      >
                        <i className="ti ti-calendar me-1" />
                        {filters.attendanceStats}
                      </Link>
                      <ul className="dropdown-menu dropdown-menu-end p-3">
                        {yearOptions.map((year) => (
                          <li key={year}>
                            <Link
                              to="#"
                              className="dropdown-item rounded-1"
                              onClick={() =>
                                handleYearChange("attendanceStats", year)
                              }
                            >
                              {year}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  <div className="row align-items-center">
                    <div className="col-sm-6">
                      <div className="mb-3">
                        <span className="d-block mb-1">Total Leaves</span>
                        <h4>{dashboardData?.leaveStats?.totalLeavesAllowed}</h4>
                      </div>
                    </div>
                    <div className="col-sm-6">
                      <div className="mb-3">
                        <span className="d-block mb-1">taken</span>
                        <h4>{dashboardData?.leaveStats?.takenLeaves}</h4>
                      </div>
                    </div>
                    <div className="col-sm-6">
                      <div className="mb-3">
                        <span className="d-block mb-1">Absent</span>
                        <h4>{dashboardData?.attendanceStats?.absent}</h4>
                      </div>
                    </div>
                    <div className="col-sm-6">
                      <div className="mb-3">
                        <span className="d-block mb-1">Request</span>
                        <h4>{dashboardData?.leaveStats?.requestedLeaves}</h4>
                      </div>
                    </div>
                    <div className="col-sm-6">
                      <div className="mb-3">
                        <span className="d-block mb-1">Worked Days</span>
                        <h4>{dashboardData?.attendanceStats?.workedDays}</h4>
                      </div>
                    </div>
                    <div className="col-sm-6">
                      <div className="mb-3">
                        <span className="d-block mb-1">Loss of Pay</span>
                        <h4>{dashboardData?.leaveStats?.lossOfPay}</h4>
                      </div>
                    </div>
                    <div className="col-sm-12">
                      <div>
                        <Link
                          to="#"
                          className="btn btn-dark w-100"
                          data-bs-toggle="modal"
                          data-inert={true}
                          data-bs-target="#add_leaves"
                        >
                          Apply New Leave
                        </Link>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="row">
            <div className="col-xl-4 d-flex">
              <div className="card flex-fill border-primary attendance-bg">
                <div className="card-body">
                  <div className="mb-4 text-center">
                    <h6 className="fw-medium text-gray-5 mb-1">Attendance</h6>
                    <h4>{formattedMins}</h4>
                  </div>
                  <CircleProgress
                    working_hour={expectedSeconds}
                    time={leftover}
                  />
                  ;
                  <div className="text-center">
                    {isPunchIn && checkInTime && (
                      <h6 className="fw-medium d-flex align-items-center justify-content-center mb-4">
                        <i className="ti ti-fingerprint text-primary me-1" />
                        {leftover.isTimerExpired
                          ? "Auto-Punched Out"
                          : `Punch In at ${convertUtcToTimeZone(
                              checkInTime,
                              dashboardData?.employeeDetails?.timeZone || ""
                            )}`}
                      </h6>
                    )}

                    {!isPunchIn || leftover.isTimerExpired ? (
                      <>
                        <Link
                          to="#"
                          className="btn btn-success w-100"
                          onClick={() => handlePunchIn(socket, setPunchInError)}
                        >
                          Punch In
                        </Link>

                        {punchInError && (
                          <div className="alert alert-danger mt-2 text-center">
                            {punchInError}
                          </div>
                        )}
                      </>
                    ) : (
                      <>
                        <button
                          className={`btn btn-danger w-100 mb-2 ${
                            isPunchingOut ? "disabled" : ""
                          }`}
                          disabled={
                            !(
                              leftover.hrs === 0 &&
                              leftover.mins === 0 &&
                              leftover.secs === 0
                            ) || isPunchingOut
                          }
                          onClick={handlePunchOut}
                        >
                          {isPunchingOut ? (
                            <span
                              className="spinner-border spinner-border-sm"
                              role="status"
                              aria-hidden="true"
                            ></span>
                          ) : (
                            "Punch Out"
                          )}
                        </button>

                        {!isOnBreak ? (
                          <button
                            className="btn btn-warning w-100"
                            onClick={() => handleBreakStart(socket)}
                          >
                            Start Break
                          </button>
                        ) : (
                          <button
                            className="btn btn-outline-secondary w-100"
                            onClick={() =>
                              handleEndBreak(socket, setEndBreakError)
                            }
                          >
                            Resume Work
                          </button>
                        )}
                        {punchOutError && (
                          <div className="alert alert-danger mt-2 text-center">
                            {punchOutError}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-8 d-flex">
              <div className="row flex-fill">
                <div className="col-xl-3 col-md-6">
                  <div className="card">
                    <div className="card-body">
                      <div className="border-bottom mb-3 pb-2">
                        <span className="avatar avatar-sm bg-primary mb-2">
                          <i className="ti ti-clock-stop" />
                        </span>
                        <h2 className="mb-2">
                          {dashboardData?.workingHoursStats?.today?.workedHours}{" "}
                          /{" "}
                          <span className="fs-20 text-gray-5">
                            {
                              dashboardData?.workingHoursStats?.today
                                ?.expectedHours
                            }
                          </span>
                        </h2>
                        <p className="fw-medium text-truncate">
                          Total Hours Today
                        </p>
                      </div>
                      {/* <div>
                        <p className="d-flex align-items-center fs-13">
                          <span className="avatar avatar-xs rounded-circle bg-success flex-shrink-0 me-2">
                            <i className="ti ti-arrow-up fs-12" />
                          </span>
                          <span>5% This Week</span>
                        </p>
                      </div> */}
                    </div>
                  </div>
                </div>
                <div className="col-xl-3 col-md-6">
                  <div className="card">
                    <div className="card-body">
                      <div className="border-bottom mb-3 pb-2">
                        <span className="avatar avatar-sm bg-dark mb-2">
                          <i className="ti ti-clock-up" />
                        </span>
                        <h2 className="mb-2">
                          {
                            dashboardData?.workingHoursStats?.thisWeek
                              ?.workedHours
                          }{" "}
                          /{" "}
                          <span className="fs-20 text-gray-5">
                            {" "}
                            {
                              dashboardData?.workingHoursStats?.thisWeek
                                ?.expectedHours
                            }
                          </span>
                        </h2>
                        <p className="fw-medium text-truncate">
                          Total Hours Week
                        </p>
                      </div>
                      {/* <div>
                        <p className="d-flex align-items-center fs-13">
                          <span className="avatar avatar-xs rounded-circle bg-success flex-shrink-0 me-2">
                            <i className="ti ti-arrow-up fs-12" />
                          </span>
                          <span>7% Last Week</span>
                        </p>
                      </div> */}
                    </div>
                  </div>
                </div>
                <div className="col-xl-3 col-md-6">
                  <div className="card">
                    <div className="card-body">
                      <div className="border-bottom mb-3 pb-2">
                        <span className="avatar avatar-sm bg-info mb-2">
                          <i className="ti ti-calendar-up" />
                        </span>
                        <h2 className="mb-2">
                          {
                            dashboardData?.workingHoursStats?.thisMonth
                              ?.workedHours
                          }{" "}
                          /{" "}
                          <span className="fs-20 text-gray-5">
                            {" "}
                            {
                              dashboardData?.workingHoursStats?.thisMonth
                                ?.expectedHours
                            }
                          </span>
                        </h2>
                        <p className="fw-medium text-truncate">
                          Total Hours Month
                        </p>
                      </div>
                      {/* <div>
                        <p className="d-flex align-items-center fs-13 text-truncate">
                          <span className="avatar avatar-xs rounded-circle bg-danger flex-shrink-0 me-2">
                            <i className="ti ti-arrow-down fs-12" />
                          </span>
                          <span>8% Last Month</span>
                        </p>
                      </div> */}
                    </div>
                  </div>
                </div>
                <div className="col-xl-3 col-md-6">
                  <div className="card">
                    <div className="card-body">
                      <div className="border-bottom mb-3 pb-2">
                        <span className="avatar avatar-sm bg-pink mb-2">
                          <i className="ti ti-calendar-star" />
                        </span>
                        <h2 className="mb-2">
                          {
                            dashboardData?.workingHoursStats?.thisMonth
                              ?.overtimeHours
                          }{" "}
                          /{" "}
                          <span className="fs-20 text-gray-5">
                            {" "}
                            {
                              dashboardData?.workingHoursStats?.thisMonth
                                ?.overtimeHours
                            }
                          </span>
                        </h2>
                        <p className="fw-medium text-truncate">
                          Overtime this Month
                        </p>
                      </div>
                      {/* <div>
                        <p className="d-flex align-items-center fs-13 text-truncate">
                          <span className="avatar avatar-xs rounded-circle bg-danger flex-shrink-0 me-2">
                            <i className="ti ti-arrow-down fs-12" />
                          </span>
                          <span>6% Last Month</span>
                        </p>
                      </div> */}
                    </div>
                  </div>
                </div>
                <div className="col-md-12">
                  <div className="card">
                    <div className="card-body">
                      <div className="row">
                        <div className="col-xl-3">
                          <div className="mb-4">
                            <p className="d-flex align-items-center mb-1">
                              <i className="ti ti-point-filled text-dark-transparent me-1" />
                              Total Working hours
                            </p>
                            <h3>
                              {convertHoursDecimalToHoursMinutes(
                                dashboardData?.workingHoursStats?.today
                                  ?.expectedHours ?? 0
                              )}
                            </h3>
                          </div>
                        </div>
                        <div className="col-xl-3">
                          <div className="mb-4">
                            <p className="d-flex align-items-center mb-1">
                              <i className="ti ti-point-filled text-success me-1" />
                              Productive Hours
                            </p>
                            <h3>
                              {convertHoursDecimalToHoursMinutes(
                                dashboardData?.workingHoursStats?.today
                                  ?.workedHours ?? 0
                              )}
                            </h3>
                          </div>
                        </div>
                        <div className="col-xl-3">
                          <div className="mb-4">
                            <p className="d-flex align-items-center mb-1">
                              <i className="ti ti-point-filled text-warning me-1" />
                              Break hours
                            </p>
                            <h3>
                              {convertHoursDecimalToHoursMinutes(
                                dashboardData?.workingHoursStats?.today
                                  ?.breakHours ?? 0
                              )}
                            </h3>
                          </div>
                        </div>
                        <div className="col-xl-3">
                          <div className="mb-4">
                            <p className="d-flex align-items-center mb-1">
                              <i className="ti ti-point-filled text-info me-1" />
                              Overtime
                            </p>
                            <h3>
                              {convertHoursDecimalToHoursMinutes(
                                dashboardData?.workingHoursStats?.today
                                  ?.overtimeHours ?? 0
                              )}
                            </h3>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="row">
            <div className="col-xl-6 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap row-gap-2">
                    <h5>Projects</h5>
                    <div className="dropdown">
                      <Link
                        to="#"
                        className="btn btn-white border-0 dropdown-toggle border btn-sm d-inline-flex align-items-center"
                        data-bs-toggle="dropdown"
                      >
                        {filters.projects}
                      </Link>
                      <ul className="dropdown-menu  dropdown-menu-end p-3">
                        <li>
                          <Link
                            to="#"
                            className="dropdown-item rounded-1"
                            onClick={() => handleProjectFilterChange("all")}
                          >
                            All Projects
                          </Link>
                        </li>
                        <li>
                          <Link
                            to="#"
                            className="dropdown-item rounded-1"
                            onClick={() => handleProjectFilterChange("ongoing")}
                          >
                            Ongoing Projects
                          </Link>
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  {dashboardData?.projects?.length === 0 ? (
                    <p className="text-center text-gray-500 text-lg">
                      No available projects
                    </p>
                  ) : (
                    <div className="row">
                      {dashboardData?.projects?.map((project) => (
                        <div key={project.projectId} className="col-md-6 mb-4">
                          <div className="card shadow-none h-100">
                            <div className="card-body">
                              <div className="d-flex align-items-center justify-content-between mb-3">
                                <h6>{project.projectTitle}</h6>
                                <div className="dropdown">
                                  <Link
                                    to="#"
                                    className="d-inline-flex align-items-center"
                                    data-bs-toggle="dropdown"
                                  >
                                    <i className="ti ti-dots-vertical" />
                                  </Link>
                                  <ul className="dropdown-menu dropdown-menu-end p-3">
                                    <li>
                                      <Link
                                        to="#"
                                        className="dropdown-item rounded-1"
                                        data-bs-toggle="modal"
                                        data-bs-target="#edit_task"
                                      >
                                        <i className="ti ti-edit me-2" /> Edit
                                      </Link>
                                    </li>
                                    <li>
                                      <Link
                                        to="#"
                                        className="dropdown-item rounded-1"
                                        data-bs-toggle="modal"
                                        data-bs-target="#delete_modal"
                                      >
                                        <i className="ti ti-trash me-2" />{" "}
                                        Delete
                                      </Link>
                                    </li>
                                  </ul>
                                </div>
                              </div>

                              {/* Leader */}
                              <div className="d-flex align-items-center mb-3">
                                <Link to="#" className="avatar">
                                  <img
                                    src={
                                      project.projectLeadAvatar ||
                                      "assets/img/users/user-placeholder.jpg"
                                    }
                                    className="img-fluid rounded-circle"
                                    alt="lead"
                                  />
                                </Link>
                                <div className="ms-2">
                                  <h6 className="fw-normal">
                                    <Link to="#">
                                      {project.leadName || "N/A"}
                                    </Link>
                                  </h6>
                                  <span className="fs-13 d-block">
                                    Project Leader
                                  </span>
                                </div>
                              </div>

                              {/* Deadline */}
                              <div className="d-flex align-items-center mb-3">
                                <Link
                                  to="#"
                                  className="avatar bg-soft-primary rounded-circle"
                                >
                                  <i className="ti ti-calendar text-primary fs-16" />
                                </Link>
                                <div className="ms-2">
                                  <h6 className="fw-normal">
                                    {formatDateProject(project.dueDate)}
                                  </h6>
                                  <span className="fs-13 d-block">
                                    Deadline
                                  </span>
                                </div>
                              </div>

                              {/* Tasks + Avatars */}
                              <div className="d-flex align-items-center justify-content-between bg-transparent-light border rounded p-2 ">
                                <div className="d-flex align-items-center">
                                  <span className="avatar avatar-sm bg-success-transparent rounded-circle me-1">
                                    <i className="ti ti-checklist fs-16" />
                                  </span>
                                  <p>
                                    Tasks :{" "}
                                    <span className="text-gray-9">
                                      {project.completedTasks}
                                    </span>{" "}
                                    / {project.totalTasks}
                                  </p>
                                </div>
                                <div className="avatar-list-stacked avatar-group-sm">
                                  {project.membersAvatars
                                    .slice(0, 3)
                                    .map((avatarUrl, idx) => (
                                      <span
                                        key={idx}
                                        className="avatar avatar-rounded"
                                      >
                                        <img
                                          className="border border-white"
                                          src={
                                            avatarUrl ||
                                            "assets/img/profiles/avatar-31.jpg"
                                          }
                                          alt="member"
                                        />
                                      </span>
                                    ))}
                                  {project.membersAvatars.length > 3 && (
                                    <Link
                                      className="avatar bg-primary avatar-rounded text-fixed-white fs-12 fw-medium"
                                      to="#"
                                    >
                                      +{project.membersAvatars.length - 3}
                                    </Link>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
            <div className="col-xl-6 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap row-gap-2">
                    <h5>Tasks</h5>
                    <div className="dropdown">
                      <Link
                        to="#"
                        className="btn btn-white border-0 dropdown-toggle border btn-sm d-inline-flex align-items-center"
                        data-bs-toggle="dropdown"
                      >
                        All Projects
                      </Link>
                      <ul className="dropdown-menu  dropdown-menu-end p-3">
                        <li>
                          <Link
                            to="#"
                            className="dropdown-item rounded-1"
                            onClick={() => handleTaskChange("all")}
                          >
                            All Projects
                          </Link>
                        </li>
                        <li>
                          <Link
                            to="#"
                            className="dropdown-item rounded-1"
                            onClick={() => handleTaskChange("ongoing")}
                          >
                            Ongoing Projects
                          </Link>
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  <div className="list-group list-group-flush">
                    {dashboardData?.tasks?.map((task) => (
                      <div
                        key={task._id}
                        className="list-group-item border rounded mb-3 p-2"
                      >
                        <div className="row align-items-center row-gap-3">
                          <div className="col-md-8">
                            <div className="todo-inbox-check d-flex align-items-center">
                              <span>
                                <i className="ti ti-grid-dots me-2" />
                              </span>
                              <div className="form-check">
                                <input
                                  className="form-check-input"
                                  type="checkbox"
                                  defaultChecked={task.checked}
                                />
                              </div>
                              <span className="me-2 d-flex align-items-center rating-select">
                                <i
                                  className={`ti ${
                                    task.starred
                                      ? "ti-star-filled filled"
                                      : "ti-star"
                                  }`}
                                />
                              </span>
                              <div className="strike-info">
                                <h4 className="fs-14 text-truncate">
                                  {task.title}
                                </h4>
                              </div>
                            </div>
                          </div>
                          <div className="col-md-4">
                            <div className="d-flex align-items-center justify-content-md-end flex-wrap row-gap-3">
                              <span
                                className={`badge d-inline-flex align-items-center me-2 ${getStatusBadgeClass(
                                  task.status
                                )}`}
                              >
                                <i className="fas fa-circle fs-6 me-1" />
                                {task.status}
                              </span>
                              <div className="d-flex align-items-center">
                                <div className="avatar-list-stacked avatar-group-sm">
                                  {task.avatars.slice(0, 3).map((member) => (
                                    <span
                                      key={member._id}
                                      className="avatar avatar-rounded"
                                    >
                                      {member.avatar ? (
                                        <img
                                          className="border border-white"
                                          src={
                                            member.avatar ||
                                            "assets/img/profiles/avatar-31.jpg"
                                          }
                                          alt="member"
                                        />
                                      ) : (
                                        <span className="avatar bg-secondary avatar-rounded text-white">
                                          U
                                        </span>
                                      )}
                                    </span>
                                  ))}
                                  {task.avatars.length > 3 && (
                                    <span className="avatar bg-primary avatar-rounded text-fixed-white fs-12 fw-medium">
                                      +{task.avatars.length - 3}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="row">
            <div className="col-xl-5 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap row-gap-2">
                    <h5>Performance</h5>
                    <div className="dropdown">
                      <Link
                        to="#"
                        className="btn btn-white border btn-sm d-inline-flex align-items-center"
                        data-bs-toggle="dropdown"
                      >
                        <i className="ti ti-calendar me-1" />
                        {filters.performance}
                      </Link>
                      <ul className="dropdown-menu  dropdown-menu-end p-3">
                        {yearOptions.map((year) => (
                          <li key={year}>
                            <Link
                              to="#"
                              className="dropdown-item rounded-1"
                              onClick={() =>
                                handleYearChange("performance", year)
                              }
                            >
                              {year}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  <div>
                    <div className="bg-light d-flex align-items-center rounded p-2">
                      <h3 className="me-2">98%</h3>
                      <span className="badge badge-outline-success bg-success-transparent rounded-pill me-1">
                        12%
                      </span>
                      <span>vs last years</span>
                    </div>
                    {performance_chart2_series.length === months.length &&
                    performance_chart2_series.length > 0 ? (
                      <ReactApexChart
                        options={{
                          ...performance_chart2_options,
                          xaxis: {
                            ...performance_chart2_options.xaxis,
                            categories: months,
                          },
                        }}
                        series={[
                          {
                            name: "Monthly Salary",
                            data: performance_chart2_series,
                          },
                        ]}
                        type="area"
                        height={288}
                      />
                    ) : (
                      <div>Loading performance...</div>
                    )}
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-4 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap row-gap-2">
                    <h5>My Skills</h5>
                    <div className="dropdown">
                      <Link
                        to="#"
                        className="btn btn-white border btn-sm d-inline-flex align-items-center"
                        data-bs-toggle="dropdown"
                      >
                        <i className="ti ti-calendar me-1" />
                        {filters.skills}
                      </Link>
                      <ul className="dropdown-menu  dropdown-menu-end p-3">
                        {yearOptions.map((year) => (
                          <li key={year}>
                            <Link
                              to="#"
                              className="dropdown-item rounded-1"
                              onClick={() => handleYearChange("skills", year)}
                            >
                              {year}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  <div>
                    {dashboardData?.skills?.length === 0 && (
                      <div className="text-muted text-center">
                        No skills available.
                      </div>
                    )}
                    {dashboardData?.skills?.map((skill, idx) => {
                      const borderColors = [
                        "border-primary",
                        "border-success",
                        "border-purple",
                        "border-info",
                        "border-dark",
                      ];
                      const colorClass =
                        borderColors[idx % borderColors.length];
                      const dateObj = new Date(skill.updatedAt);
                      const formattedDate = dateObj.toLocaleDateString(
                        "en-GB",
                        { day: "2-digit", month: "short", year: "numeric" }
                      );
                      return (
                        <div
                          key={skill.name}
                          className="border border-dashed bg-transparent-light rounded p-2 mb-2"
                        >
                          <div className="d-flex align-items-center justify-content-between">
                            <div className="d-flex align-items-center">
                              <span
                                className={`d-block border border-2 h-12 ${colorClass} border-red rounded-5 me-2`}
                                style={{ width: 2, minWidth: 2, height: 10 }}
                              />
                              <div>
                                <h6 className="fw-medium mb-1">{skill.name}</h6>
                                <p>Updated : {formattedDate}</p>
                              </div>
                            </div>
                            <CircleProgressSmall value={skill.proficiency} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 d-flex">
              <div className="flex-fill">
                <div className="card card-bg-5 bg-dark mb-3">
                  <div className="card-body">
                    <div className="text-center">
                      <h5 className="text-white mb-4">Team Birthday</h5>
                      {dashboardData?.birthdays &&
                      dashboardData?.birthdays.length > 0 ? (
                        dashboardData?.birthdays.map((birthday) => (
                          <div key={birthday._id} className="mb-4">
                            <span className="avatar avatar-xl avatar-rounded mb-2">
                              <ImageWithBasePath
                                src={
                                  birthday.avatarUrl ||
                                  "assets/img/users/default-avatar.jpg"
                                }
                                alt={birthday.name}
                              />
                            </span>
                            <div className="mb-3">
                              <h6 className="text-white fw-medium mb-1">
                                {birthday.name}
                              </h6>
                              <p>{birthday.role || "—"}</p>
                            </div>
                            <Link to="#" className="btn btn-sm btn-primary">
                              Send Wishes
                            </Link>
                          </div>
                        ))
                      ) : (
                        <div className="text-white-50">
                          No team birthdays today.
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                <div className="card bg-secondary mb-3">
                  <div className="card-body d-flex align-items-center justify-content-between p-3">
                    <div>
                      <h5 className="text-white mb-1">Leave Policy</h5>
                      <p className="text-white">Last Updated : Today</p>
                    </div>
                    <Link to="#" className="btn btn-white btn-sm px-3">
                      View All
                    </Link>
                  </div>
                </div>
                <div className="card bg-warning">
                  <div className="card-body d-flex align-items-center justify-content-between p-3">
                    <div>
                      <h5 className="mb-1">Next Holiday</h5>
                      <p className="text-gray-9">Diwali, 15 Sep 2025</p>
                    </div>
                    <Link
                      to="holidays.html"
                      className="btn btn-white btn-sm px-3"
                    >
                      View All
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="row">
            <div className="col-xl-4 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap">
                    <h5>Team Members</h5>
                    <div>
                      <Link to="#" className="btn btn-light btn-sm">
                        View All
                      </Link>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  {dashboardData?.teamMembers?.length === 0 && (
                    <p className="text-muted text-center">
                      No team members available.
                    </p>
                  )}

                  {dashboardData?.teamMembers?.map((member) => (
                    <div
                      className="d-flex align-items-center justify-content-between mb-4"
                      key={member._id}
                    >
                      <div className="d-flex align-items-center">
                        <Link to="#" className="avatar flex-shrink-0">
                          <ImageWithBasePath
                            src={
                              member.avatar ||
                              "assets/img/profiles/avatar-31.jpg"
                            }
                            className="rounded-circle border border-2"
                            alt={`${member.name}'s avatar`}
                          />
                        </Link>
                        <div className="ms-2">
                          <h6 className="fs-14 fw-medium text-truncate mb-1">
                            <Link to="#">{member.name}</Link>
                          </h6>
                          <p className="fs-13">{member.role}</p>
                        </div>
                      </div>
                      <div className="d-flex align-items-center">
                        <Link
                          to="#"
                          className="btn btn-light btn-icon btn-sm me-2"
                          title="Call"
                        >
                          <i className="ti ti-phone fs-16" />
                        </Link>
                        <Link
                          to="#"
                          className="btn btn-light btn-icon btn-sm me-2"
                          title="Mail"
                        >
                          <i className="ti ti-mail-bolt fs-16" />
                        </Link>
                        <Link
                          to="#"
                          className="btn btn-light btn-icon btn-sm"
                          title="Chat"
                        >
                          <i className="ti ti-brand-hipchat fs-16" />
                        </Link>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="col-xl-4 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap">
                    <h5>Notifications</h5>
                    <div>
                      <Link to="#" className="btn btn-light btn-sm">
                        View All
                      </Link>
                    </div>
                  </div>
                </div>
                <div className="card-body">
                  {dashboardData?.notifications?.length === 0 && (
                    <p className="text-muted text-center">
                      No new notifications
                    </p>
                  )}
                  {dashboardData?.notifications?.map((notification) => (
                    <div
                      className="d-flex align-items-start mb-4"
                      key={notification._id}
                    >
                      <Link to="#" className="avatar flex-shrink-0">
                        <ImageWithBasePath
                          src={
                            notification.avatar ||
                            "assets/img/profiles/avatar-31.jpg"
                          }
                          className="rounded-circle border border-2"
                          alt="Avatar"
                        />
                      </Link>
                      <div className="ms-2">
                        <h6 className="fs-14 fw-medium text-truncate mb-1">
                          {notification.title}
                        </h6>
                        <p className="fs-13 mb-0">
                          {new Date(notification.createdAt).toLocaleString(
                            "en-US",
                            {
                              hour: "2-digit",
                              minute: "2-digit",
                              hour12: true,
                              day: "2-digit",
                              month: "short",
                            }
                          )}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="col-xl-4 d-flex">
              <div className="card flex-fill">
                <div className="card-header">
                  <div className="d-flex align-items-center justify-content-between flex-wrap row-gap-2">
                    <h5>Meetings Schedule</h5>
                    <div className="dropdown">
                      <Link
                        to="#"
                        className="btn btn-white border btn-sm d-inline-flex align-items-center"
                        data-bs-toggle="dropdown"
                      >
                        <i className="ti ti-calendar me-1" />
                        <span>
                          {filters.meetings === "today"
                            ? "Today"
                            : filters.meetings === "month"
                            ? "This Month"
                            : "This Year"}
                        </span>
                      </Link>
                      <ul className="dropdown-menu  dropdown-menu-end p-3">
                        <li>
                          <Link
                            to="#"
                            className="dropdown-item rounded-1"
                            onClick={() => handleMeetingFilterChange("today")}
                          >
                            Today
                          </Link>
                        </li>
                        <li>
                          <Link
                            to="#"
                            className="dropdown-item rounded-1"
                            onClick={() => handleMeetingFilterChange("month")}
                          >
                            This Month
                          </Link>
                        </li>
                        <li>
                          <Link
                            to="#"
                            className="dropdown-item rounded-1"
                            onClick={() => handleMeetingFilterChange("year")}
                          >
                            This Year
                          </Link>
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="card-body schedule-timeline">
                  {dashboardData?.meetings?.length === 0 && (
                    <div className="text-muted text-center">
                      No meetings scheduled.
                    </div>
                  )}
                  {dashboardData?.meetings?.map((meeting) => {
                    let colorClass = "text-primary";
                    switch ((meeting.tag || "").toLowerCase()) {
                      case "review":
                        colorClass = "text-secondary";
                        break;
                      case "celebration":
                        colorClass = "text-warning";
                        break;
                      case "development":
                        colorClass = "text-success";
                        break;
                      default:
                        colorClass = "text-primary";
                    }
                    return (
                      <div
                        className="d-flex align-items-start"
                        key={meeting._id}
                      >
                        <div className="d-flex align-items-center active-time">
                          <span>
                            {new Date(meeting.startTime).toLocaleTimeString(
                              [],
                              {
                                hour: "2-digit",
                                minute: "2-digit",
                              }
                            )}
                          </span>
                          <span>
                            <i
                              className={`ti ti-point-filled ${colorClass} fs-20`}
                            />
                          </span>
                        </div>
                        <div className="flex-fill ps-3 pb-4 timeline-flow">
                          <div className="bg-light p-2 rounded">
                            <p className="fw-medium text-gray-9 mb-1">
                              {meeting.title}
                            </p>
                            <span>{meeting.tag}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="footer d-sm-flex align-items-center justify-content-between border-top bg-white p-3">
          <p className="mb-0">2014 - 2025 © Amasqis.</p>
          <p>
            Designed &amp; Developed By{" "}
            <Link to="https://amasqis.ai" className="text-primary">
              Amasqis
            </Link>
          </p>
        </div>
      </div>
      <RequestModals
        onLeaveRequestCreated={() => {
          if (socket) {
            socket?.emit("admin/dashboard/get-all-data", { year: currentYear });
          }
        }}
      />
    </>
  );
};

export default EmployeeDashboard;
