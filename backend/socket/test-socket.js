import { io } from "socket.io-client";
import { ObjectId } from "mongodb";

const socket = io("http://localhost:5000", {
  auth: {
    token:
      "eyJhbGciOiJSUzI1NiIsImNhdCI6ImNsX0I3ZDRQRDExMUFBQSIsImtpZCI6Imluc18ydWhlckRvSzVNRnFUTERtUzRhQ0dXenB6Y2EiLCJ0eXAiOiJKV1QifQ.eyJhenAiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJleHAiOjE3NTM2NDM1NzQsImZ2YSI6WzYwMTgsLTFdLCJpYXQiOjE3NTM2NDM1MTQsImlzcyI6Imh0dHBzOi8vdXAtc2tpbmstNC5jbGVyay5hY2NvdW50cy5kZXYiLCJuYmYiOjE3NTM2NDM1MDQsInNpZCI6InNlc3NfMzBIUkJreTZKRldiSDBnTEhIQlFpWlVEeTh4Iiwic3ViIjoidXNlcl8yempXYW9tMnRIdUxsTXJycjgxZFF4SWJXV3MifQ.ki4n8RVVBWrrSyOdm0-tdwUSEc-Fms4E8HUfly1LcXDFiUJwuLrEsLYAzV06zNdR6QIa3ZwnYRpAE9ofjO6HxTZcS0fzj-8XCS_AGxkiDFFpNYDw5OgdKj05bqXaJ0NUcmu5vibN__c8cKyBVLPIywH85-NcuVeVgePcs_42AJdCzVNZtw5QOOah0l6Hckcr0HkFMpogYForx-ijza0vTfdAzjzsFWpDPOifGrjJ4j1q8RCgx75k4CLNPvbvht9GZ7SQeEf_rJzL0tQciZVLH_O2mWuYTYlWTBZQ8DaBqTv8EftDP63TFxDrOyRFAhiq7mBf9gJ5gcFrjwxqjnB2nw",
  },
});
const payload = {
  year: 2023,
};

socket.on("connect", () => {
  console.log("✅ Connected with ID:", socket.id);
  console.log("hello");
  socket.emit("employee/dashboard/get-all-data");
});

socket.on("employee/dashboard/get-all-data-response", (data) => {
  console.log("📥 Employees list response:", data);
  socket.disconnect();
});

socket.on("connect_error", (err) => {
  console.error("❌ Connection error:", err.message);
});
