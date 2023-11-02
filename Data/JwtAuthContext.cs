using UserJourney.WebAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace UserJourney.WebAPI.Data;

public partial class JwtAuthContext : DbContext
{
    public JwtAuthContext()
    {
    }

    public JwtAuthContext(DbContextOptions<JwtAuthContext> options)
        : base(options)
    {
    }

    public virtual DbSet<ResetPassword> ResetPasswords { get; set; }

    public virtual DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ResetPassword>(entity =>
        {
            entity.HasKey(e => e.ResetPasswordId).HasName("PK__ResetPas__805BA24260852CA6");

            entity.ToTable("ResetPassword");

            entity.Property(e => e.ResetPasswordId).HasColumnName("ResetPasswordID");
            entity.Property(e => e.AddedAt)
                .HasDefaultValueSql("(getdate())")
                .HasColumnType("datetime")
                .HasColumnName("Added_At");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("(getdate())")
                .HasColumnType("datetime")
                .HasColumnName("Created_At");
            entity.Property(e => e.Email)
                .HasMaxLength(200)
                .IsUnicode(false);
            entity.Property(e => e.ExpiryTime).HasDefaultValueSql("((5))");
            entity.Property(e => e.IsActive)
                .IsRequired()
                .HasDefaultValueSql("((1))");
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.Property(e => e.UserId).HasColumnName("UserID");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("(getdate())")
                .HasColumnType("datetime")
                .HasColumnName("Created_At");
            entity.Property(e => e.Email)
                .HasMaxLength(100)
                .IsUnicode(false);
            entity.Property(e => e.FullName)
                .HasMaxLength(200)
                .IsUnicode(false);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
